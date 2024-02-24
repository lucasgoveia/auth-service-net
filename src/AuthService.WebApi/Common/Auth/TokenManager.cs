using System.IdentityModel.Tokens.Jwt;
using System.Runtime.CompilerServices;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using AuthService.Common.Caching;
using AuthService.Common.Results;
using AuthService.Common.Timestamp;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

namespace AuthService.WebApi.Common.Auth;

public interface ITokenManager
{
    string GenerateAccessToken(long userId, long identityId);
    Task<Result<string>> RefreshToken(CancellationToken ct = default);
    Task<bool> IsAccessTokenRevoked(long userId, string accessToken, CancellationToken ct = default);
    Task GenerateAndSetRefreshToken();
    Task RemoveRefreshToken();
    Task RevokeAccessToken();
    Task<RefreshTokenInfo?> GetRefreshTokenInfo();
    string GenerateResetPasswordAccessToken(long userId, long identityId);
    Task RevokeUserAccessTokens(long userId);
}

public record RefreshTokenInfo
{
    public int UsageCount { get; init; }
    public bool TrustedDevice { get; init; }
}

public class TokenManager(UtcNow utcNow, IOptions<JwtConfig> jwtConfig, ISessionManager sessionManager,
        IHttpContextAccessor httpContextAccessor, ICacher cacher, RsaKeyHolder rsaKeyHolder, ILogger<TokenManager> logger)
    : ITokenManager
{
    private readonly JwtConfig _jwtConfig = jwtConfig.Value;

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static string BuildRefreshTokenKey(long accountId, string sessionId, string refreshToken) =>
        $"accounts:{accountId}:sessions:{sessionId}:refresh-token:{refreshToken}";

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static string BuildRevokedAccessTokenKey(long accountId, string accessToken) =>
        $"accounts:{accountId}:revoked-access-tokens:{accessToken}";
    
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static string BuildGlobalAccessTokenRevocationKey(long accountId) =>
        $"accounts:{accountId}:last-global-access-token-revocation";

    private TimeSpan GetRefreshTokenLifetime(bool trustedDevice)
    {
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
        logger.LogInformation("Generating and setting refresh token for {userId} with {expiration}", session.UserId, expiration);
        
        var refreshToken = GenerateRefreshToken(session.UserId, session.IdentityId,
            session.SessionSecret, expiration);

        await cacher.Set(
            BuildRefreshTokenKey(session.UserId, session.SessionId, refreshToken),
            new RefreshTokenInfo { TrustedDevice = session.TrustedDevice, UsageCount = 0 },
            expiration
        );

        httpContextAccessor.HttpContext!.Response.Cookies.Append(AuthCookieNames.RefreshTokenCookieName, refreshToken,
            new CookieOptions
            {
                Secure = true,
                Path = "/",
                HttpOnly = true,
                Expires = utcNow().Add(expiration),
                MaxAge = expiration,
                SameSite = SameSiteMode.None
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
            return SuccessResult.Success(accessToken);
        }

        await cacher.Set(BuildRefreshTokenKey(session.UserId, session.SessionId, refreshToken),
            info with { UsageCount = info.UsageCount + 1 },
            expiry);
        logger.LogInformation("Generated new access token");

        return SuccessResult.Success(GenerateAccessToken(session.UserId, session.IdentityId));
    }

    public async Task<bool> IsAccessTokenRevoked(long userId, string accessToken, CancellationToken ct = default)
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
        httpContextAccessor.HttpContext!.Response.Cookies.Delete(AuthCookieNames.RefreshTokenCookieName);
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
    
    public string GenerateAccessToken(long userId, long identityId)
    {
        return GenerateAsymmetricToken(userId, identityId, TimeSpan.FromMinutes(_jwtConfig.AccessTokenMinutesLifetime));
    }

    public string GenerateResetPasswordAccessToken(long userId, long identityId)
    {
        return GenerateSymmetricToken(userId, identityId, _jwtConfig.ResetPasswordTokenSecret,
            TimeSpan.FromMinutes(_jwtConfig.ResetPasswordTokenMinutesLifetime));
    }

    public Task RevokeUserAccessTokens(long userId)
    {
        return cacher.Set(BuildGlobalAccessTokenRevocationKey(userId), utcNow(),
            TimeSpan.FromMinutes(_jwtConfig.AccessTokenMinutesLifetime));
    }

    private string GenerateRefreshToken(long userId, long identityId, string sessionSecret, TimeSpan lifetime)
    {
        return GenerateSymmetricToken(userId, identityId, sessionSecret, lifetime);
    }

    private string GenerateSymmetricToken(long userId, long identityId, string secret, TimeSpan lifetime)
    {
        var now = utcNow();
        var claims = new[]
        {
            new Claim(JwtRegisteredClaimNames.Sub, userId.ToString()),
            new Claim(CustomJwtClaimsNames.IdentityId, identityId.ToString()),
            new Claim(JwtRegisteredClaimNames.Iat, EpochTime.GetIntDate(now).ToString(), ClaimValueTypes.Integer64)
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

    private string GenerateAsymmetricToken(long userId, long identityId, TimeSpan lifetime)
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