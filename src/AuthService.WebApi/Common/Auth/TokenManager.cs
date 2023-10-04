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
    void GenerateAndSetLimitedAccessToken(long userId, long identityId, string sessionSecret, TimeSpan lifetime);
    void RemoveLimitedAccessToken();
}

public record RefreshTokenInfo
{
    public int UsageCount { get; init; }
    public bool TrustedDevice { get; init; }
}

public class TokenManager(UtcNow utcNow, IOptions<JwtConfig> jwtConfig, ISessionManager sessionManager,
        IHttpContextAccessor httpContextAccessor, ICacher cacher)
    : ITokenManager
{
    private readonly JwtConfig _jwtConfig = jwtConfig.Value;

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static string BuildRefreshTokenKey(long accountId, string sessionId, string refreshToken) =>
        $"accounts:{accountId}:sessions:{sessionId}:refresh-token:{refreshToken}";

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static string BuildRevokedAccessTokenKey(long accountId, string accessToken) =>
        $"accounts:{accountId}:revoked-access-tokens:{accessToken}";

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
                MaxAge = expiration
            });
    }

    public async Task<Result<string>> RefreshToken(CancellationToken ct = default)
    {
        var session = (await sessionManager.GetActiveSession())!;
        var refreshToken = httpContextAccessor.HttpContext!.Request.Cookies[AuthCookieNames.RefreshTokenCookieName]!;

        var (info, expiry) =
            await cacher.GetWithExpiration<RefreshTokenInfo>(BuildRefreshTokenKey(session.UserId, session.SessionId,
                refreshToken));

        if (info!.UsageCount + 1 == _jwtConfig.RefreshTokenAllowedRenewsCount)
        {
            var newExpiration = info.TrustedDevice
                ? TimeSpan.FromHours(_jwtConfig.RefreshTokenInTrustedDevicesHoursLifetime)
                : expiry.GetValueOrDefault();

            await cacher.Remove(BuildRefreshTokenKey(session.UserId, session.SessionId, refreshToken));
            await GenerateAndSetRefreshToken(session, newExpiration);

            var accessToken = GenerateAccessToken(session.UserId, session.IdentityId);
            return SuccessResult.Success(accessToken);
        }

        await cacher.Set(BuildRefreshTokenKey(session.UserId, session.SessionId, refreshToken),
            info with { UsageCount = info.UsageCount + 1 },
            expiry);

        return SuccessResult.Success(GenerateAccessToken(session.UserId, session.IdentityId));
    }

    public async Task<bool> IsAccessTokenRevoked(long userId, string accessToken, CancellationToken ct = default)
    {
        return await cacher.Get<bool?>(BuildRevokedAccessTokenKey(userId, accessToken)) ?? false;
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
        var refreshToken = GetRefreshTokenFromCookie();
        if (string.IsNullOrEmpty(refreshToken))
            return;

        var session = (await sessionManager.GetActiveSession())!;
        httpContextAccessor.HttpContext!.Response.Cookies.Delete(AuthCookieNames.RefreshTokenCookieName);
        await cacher.Remove(BuildRefreshTokenKey(session.UserId, session.SessionId, refreshToken));
    }

    public async Task RevokeAccessToken()
    {
        var session = (await sessionManager.GetActiveSession())!;
        await cacher.Set(BuildRevokedAccessTokenKey(session.UserId, GetAccessToken()), true,
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

    public void GenerateAndSetLimitedAccessToken(long userId, long identityId, string sessionSecret, TimeSpan lifetime)
    {
        var token = GenerateSymmetricToken(userId, identityId, sessionSecret, lifetime);

        httpContextAccessor.HttpContext!.Response.Cookies.Append(AuthCookieNames.LimitedAccessToken, token,
            new CookieOptions
            {
                Secure = true,
                Path = "/",
                HttpOnly = true,
                Expires = utcNow().Add(lifetime),
                MaxAge = lifetime
            });
    }

    public void RemoveLimitedAccessToken()
    {
        httpContextAccessor.HttpContext!.Response.Cookies.Delete(AuthCookieNames.LimitedAccessToken);
    }

    public string GenerateAccessToken(long userId, long identityId)
    {
        return GenerateAsymmetricToken(userId, identityId, TimeSpan.FromMinutes(_jwtConfig.AccessTokenMinutesLifetime));
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
        var privateKeyBytes = Convert.FromBase64String(_jwtConfig.AccessTokenPrivateKey);
        using var rsa = RSA.Create(4096);
        rsa.ImportRSAPrivateKey(privateKeyBytes, out _);

        var securityKey = new RsaSecurityKey(rsa);
        var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.RsaSha256Signature)
        {
            CryptoProviderFactory = new CryptoProviderFactory { CacheSignatureProviders = false }
        };

        var now = utcNow();
        var claims = new[]
        {
            new Claim(JwtRegisteredClaimNames.Sub, userId.ToString()),
            new Claim(CustomJwtClaimsNames.IdentityId, identityId.ToString()),
            new Claim(JwtRegisteredClaimNames.Iat, EpochTime.GetIntDate(now).ToString(), ClaimValueTypes.Integer64)
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