﻿using System.Diagnostics;
using System.IdentityModel.Tokens.Jwt;
using System.Runtime.CompilerServices;
using System.Security.Claims;
using System.Text;
using AuthService.Common;
using AuthService.Common.Caching;
using AuthService.Common.Timestamp;
using LucasGoveia.Results;
using LucasGoveia.SnowflakeId;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

namespace AuthService.WebApi.Common.Auth;

public interface ITokenManager
{
    string GenerateAccessToken(SnowflakeId userId, SnowflakeId identityId);
    Task<Result<string>> RefreshToken(CancellationToken ct = default);
    Task<bool> IsAccessTokenRevoked(SnowflakeId userId, string accessToken, CancellationToken ct = default);
    Task GenerateAndSetRefreshToken();
    Task RemoveRefreshToken();
    Task RevokeAccessToken();
    Task<RefreshTokenInfo?> GetRefreshTokenInfo();
    string GenerateResetPasswordAccessToken(SnowflakeId userId, SnowflakeId identityId);
    Task RevokeUserAccessTokens(SnowflakeId userId);
}

public record RefreshTokenInfo
{
    public int UsageCount { get; init; }
    public bool TrustedDevice { get; init; }
}

public class TokenManager(
    UtcNow utcNow,
    IOptions<JwtConfig> jwtConfig,
    ISessionManager sessionManager,
    IHttpContextAccessor httpContextAccessor,
    ICacher cacher,
    RsaKeyHolder rsaKeyHolder,
    ILogger<TokenManager> logger)
    : ITokenManager
{
    private readonly JwtConfig _jwtConfig = jwtConfig.Value;

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static string BuildRefreshTokenKey(SnowflakeId accountId, string sessionId, string refreshToken) =>
        $"accounts:{accountId}:sessions:{sessionId}:refresh-token:{refreshToken}";

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static string BuildRevokedAccessTokenKey(SnowflakeId accountId, string accessToken) =>
        $"accounts:{accountId}:revoked-access-tokens:{accessToken}";

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static string BuildGlobalAccessTokenRevocationKey(SnowflakeId accountId) =>
        $"accounts:{accountId}:last-global-access-token-revocation";

    private TimeSpan GetRefreshTokenLifetime(bool trustedDevice)
    {
        logger.LogDebug("RefreshTokenInTrustedDevicesHoursLifetime: {RefreshTokenInTrustedDevicesHoursLifetime}",
            _jwtConfig.RefreshTokenInTrustedDevicesHoursLifetime);
        logger.LogDebug("RefreshTokenHoursLifetime: {RefreshTokenHoursLifetime}",
            _jwtConfig.RefreshTokenHoursLifetime);
        var refreshTokenLifetime = trustedDevice
            ? TimeSpan.FromHours(_jwtConfig.RefreshTokenInTrustedDevicesHoursLifetime)
            : TimeSpan.FromHours(_jwtConfig.RefreshTokenHoursLifetime);
        return refreshTokenLifetime;
    }

    public async Task GenerateAndSetRefreshToken()
    {
        var session = (await sessionManager.GetActiveSession())!;
        var exp = GetRefreshTokenLifetime(session.TrustedDevice);
        await GenerateAndSetRefreshToken(session, exp);
    }

    private async Task GenerateAndSetRefreshToken(Session session, TimeSpan expiration)
    {
        await ApiActivitySource.Instance.WithActivity(async activity =>
        {
            activity?.AddTag("userId", session.UserId);
            activity?.AddTag("lifetime", expiration);
            logger.LogInformation("Generating and setting refresh token for {userId} with {expiration}", session.UserId,
                expiration);

            var refreshToken = GenerateRefreshToken(session.UserId, session.IdentityId,
                session.SessionSecret, expiration);
            activity?.AddEvent(new ActivityEvent("RefreshTokenGenerated", utcNow()));

            await cacher.Set(
                BuildRefreshTokenKey(session.UserId, session.SessionId, refreshToken),
                new RefreshTokenInfo { TrustedDevice = session.TrustedDevice, UsageCount = 0 },
                expiration
            );
            activity?.AddEvent(new ActivityEvent("RefreshTokenSetOnCache", utcNow()));

            httpContextAccessor.HttpContext!.Response.Cookies.Append(AuthCookieNames.RefreshTokenCookieName,
                refreshToken,
                new CookieOptions
                {
                    Secure = true,
                    Path = "/",
                    HttpOnly = true,
                    Expires = utcNow().Add(expiration),
                    MaxAge = expiration,
                    SameSite = SameSiteMode.None
                });
            activity?.AddEvent(new ActivityEvent("RefreshTokenSetOnCookie", utcNow()));
        });
    }

    public async Task<Result<string>> RefreshToken(CancellationToken ct = default)
    {
        var session = (await sessionManager.GetActiveSession())!;
        var refreshToken = httpContextAccessor.HttpContext!.Request.Cookies[AuthCookieNames.RefreshTokenCookieName]!;

        logger.LogInformation("Refreshing token for {userId}", session.UserId);

        var (info, expiry) =
            await cacher.GetWithExpiration<RefreshTokenInfo>(BuildRefreshTokenKey(session.UserId, session.SessionId,
                refreshToken));

        if (info!.UsageCount + 1 == _jwtConfig.RefreshTokenAllowedRenewsCount)
        {
            logger.LogInformation("User refreshed with current token too many times");

            var newExpiration = info.TrustedDevice
                ? TimeSpan.FromHours(_jwtConfig.RefreshTokenInTrustedDevicesHoursLifetime)
                : expiry.GetValueOrDefault();

            logger.LogInformation("new refresh token expiration set to {newExpiration}", newExpiration);

            await cacher.Remove(BuildRefreshTokenKey(session.UserId, session.SessionId, refreshToken));
            await GenerateAndSetRefreshToken(session, newExpiration);
            logger.LogInformation("Generated new refresh token");

            var accessToken = GenerateAccessToken(session.UserId, session.IdentityId);
            logger.LogInformation("Generated new access token");
            return Result.Ok(accessToken);
        }

        await cacher.Set(BuildRefreshTokenKey(session.UserId, session.SessionId, refreshToken),
            info with { UsageCount = info.UsageCount + 1 },
            expiry);
        logger.LogInformation("Generated new access token");

        return Result.Ok(GenerateAccessToken(session.UserId, session.IdentityId));
    }

    public async Task<bool> IsAccessTokenRevoked(SnowflakeId userId, string accessToken, CancellationToken ct = default)
    {
        var token = ReadToken(accessToken);
        var tokenRevoked = await cacher.Get<bool?>(BuildRevokedAccessTokenKey(userId, token.Id)) ?? false;

        if (tokenRevoked)
            return true;

        var lastGlobalRevocation = await cacher.Get<DateTime?>(BuildGlobalAccessTokenRevocationKey(userId));

        if (lastGlobalRevocation is null)
            return false;

        return token.ValidFrom < lastGlobalRevocation;
    }

    private string? GetRefreshTokenFromCookie()
    {
        return httpContextAccessor.HttpContext!.Request.Cookies[AuthCookieNames.RefreshTokenCookieName];
    }

    private string GetAccessToken()
    {
        return httpContextAccessor.HttpContext!.Request.Headers["Authorization"].ToString()
            .Replace("Bearer ", string.Empty);
    }

    public async Task RemoveRefreshToken()
    {
        logger.LogInformation("Removing refresh token");
        var refreshToken = GetRefreshTokenFromCookie();
        if (string.IsNullOrEmpty(refreshToken))
            return;

        var session = (await sessionManager.GetActiveSession())!;
        httpContextAccessor.HttpContext!.Response.Cookies.Delete(AuthCookieNames.RefreshTokenCookieName,
            new CookieOptions
            {
                Secure = true,
                Path = "/",
                HttpOnly = true,
                Expires = utcNow().AddYears(-1),
                SameSite = SameSiteMode.None
            });
        await cacher.Remove(BuildRefreshTokenKey(session.UserId, session.SessionId, refreshToken));
    }

    private JwtSecurityToken ReadToken(string token)
    {
        return new JwtSecurityTokenHandler().ReadJwtToken(token);
    }

    public async Task RevokeAccessToken()
    {
        logger.LogInformation("Revoking {userId} access token", sessionManager.UserId!.Value);

        var token = ReadToken(GetAccessToken());
        await cacher.Set(BuildRevokedAccessTokenKey(sessionManager.UserId!.Value, token.Id), true,
            TimeSpan.FromMinutes(_jwtConfig.AccessTokenMinutesLifetime));
    }

    public async Task<RefreshTokenInfo?> GetRefreshTokenInfo()
    {
        var refreshToken = GetRefreshTokenFromCookie();
        if (string.IsNullOrEmpty(refreshToken))
            return null;

        var session = (await sessionManager.GetActiveSession())!;
        return await cacher.Get<RefreshTokenInfo>(
            BuildRefreshTokenKey(session.UserId, session.SessionId, refreshToken));
    }

    public string GenerateAccessToken(SnowflakeId userId, SnowflakeId identityId)
    {
        return ApiActivitySource.Instance.WithActivity((_) =>
            GenerateAsymmetricToken(userId, identityId, TimeSpan.FromMinutes(_jwtConfig.AccessTokenMinutesLifetime)));
    }

    public string GenerateResetPasswordAccessToken(SnowflakeId userId, SnowflakeId identityId)
    {
        return GenerateSymmetricToken(userId, identityId, _jwtConfig.ResetPasswordTokenSecret,
            TimeSpan.FromMinutes(_jwtConfig.ResetPasswordTokenMinutesLifetime));
    }

    public Task RevokeUserAccessTokens(SnowflakeId userId)
    {
        return cacher.Set(BuildGlobalAccessTokenRevocationKey(userId), utcNow(),
            TimeSpan.FromMinutes(_jwtConfig.AccessTokenMinutesLifetime));
    }

    private string GenerateRefreshToken(SnowflakeId userId, SnowflakeId identityId, string sessionSecret,
        TimeSpan lifetime)
    {
        return ApiActivitySource.Instance.WithActivity((_) =>
            GenerateSymmetricToken(userId, identityId, sessionSecret, lifetime));
    }

    private string GenerateSymmetricToken(SnowflakeId userId, SnowflakeId identityId, string secret, TimeSpan lifetime)
    {
        var now = utcNow();
        var claims = new[]
        {
            new Claim(JwtRegisteredClaimNames.Sub, userId.ToString()),
            new Claim(CustomJwtClaimsNames.IdentityId, identityId.ToString()),
            new Claim(JwtRegisteredClaimNames.Iat, EpochTime.GetIntDate(now).ToString(), ClaimValueTypes.Integer64),
            new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
        };

        var expiry = utcNow().Add(lifetime);
        var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secret));
        var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);

        var token = new JwtSecurityToken(
            issuer: _jwtConfig.Issuer,
            audience: "localhost",
            claims: claims,
            expires: expiry,
            signingCredentials: credentials,
            notBefore: now
        );

        return new JwtSecurityTokenHandler().WriteToken(token);
    }

    private string GenerateAsymmetricToken(SnowflakeId userId, SnowflakeId identityId, TimeSpan lifetime)
    {
        var securityKey = rsaKeyHolder.GetPrivateKey();

        var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.RsaSha256Signature)
        {
            CryptoProviderFactory = new CryptoProviderFactory { CacheSignatureProviders = false }
        };

        var now = utcNow();
        var claims = new[]
        {
            new Claim(JwtRegisteredClaimNames.Sub, userId.ToString()),
            new Claim(CustomJwtClaimsNames.IdentityId, identityId.ToString()),
            new Claim(JwtRegisteredClaimNames.Iat, EpochTime.GetIntDate(now).ToString(), ClaimValueTypes.Integer64),
            new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
        };

        var expiry = utcNow().Add(lifetime);

        var token = new JwtSecurityToken(
            issuer: _jwtConfig.Issuer,
            audience: "localhost",
            claims: claims,
            expires: expiry,
            signingCredentials: credentials,
            notBefore: now
        );

        return new JwtSecurityTokenHandler().WriteToken(token);
    }
}