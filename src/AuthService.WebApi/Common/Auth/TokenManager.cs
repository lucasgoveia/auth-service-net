using System.Diagnostics;
using System.Globalization;
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
    Task<string> GenerateAccessToken(SnowflakeId userId, SnowflakeId identityId);
    Task<Result<(string accessToken, string refreshToken)>> RefreshToken(CancellationToken ct = default);
    Task<bool> IsAccessTokenRevoked(SnowflakeId userId, string accessToken, CancellationToken ct = default);
    Task<string> GenerateRefreshToken();
    Task RevokeAccessToken();
    string GenerateResetPasswordAccessToken(SnowflakeId userId, SnowflakeId identityId);
    Task RevokeUserAccessTokens(SnowflakeId userId);
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
    private static string BuildRefreshTokenKey(SnowflakeId userId, Guid tokenId) =>
        $"users:{userId}:sessions:refresh-tokens:{tokenId}";

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static string BuildRevokedAccessTokenKey(SnowflakeId accountId, string accessToken) =>
        $"users:{accountId}:revoked-access-tokens:{accessToken}";

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static string BuildGlobalAccessTokenRevocationKey(SnowflakeId accountId) =>
        $"users:{accountId}:last-global-access-token-revocation";


    public async Task<string> GenerateRefreshToken()
    {
        var session = (await sessionManager.GetActiveSession())!;
        return await GenerateRefreshToken(session);
    }

    private async Task<string> GenerateRefreshToken(Session session)
    {
        return await ApiActivitySource.Instance.WithActivity(activity =>
        {
            activity?.AddTag("userId", session.UserId);

            logger.LogInformation("Generating refresh token for {userId}.", session.UserId);

            var refreshToken = GenerateRefreshToken(session.UserId, session.CredentialId, session.SessionSecret);
            activity?.AddEvent(new ActivityEvent("RefreshTokenGenerated", utcNow()));

            return Task.FromResult(refreshToken);
        });
    }


    public async Task<Result<(string accessToken, string refreshToken)>> RefreshToken(CancellationToken ct = default)
    {
        var refreshTokenStr = httpContextAccessor.HttpContext!.Request.Cookies[AuthCookieNames.RefreshTokenCookieName]!;
        var refreshToken = ReadToken(refreshTokenStr);
        var tokenId = Guid.Parse(refreshToken.Id);

        var session = (await sessionManager.GetActiveSession())!;


        logger.LogInformation("Refreshing token for {userId}", session.UserId);

        var tokenUsages = await cacher.Get<int>(BuildRefreshTokenKey(session.UserId, tokenId));

        if (tokenUsages >= 1)
        {
            logger.LogInformation("Token has been used too many times");
            await sessionManager.TerminateSession();
            return Result.Unauthorized();
        }

        await cacher.Set(BuildRefreshTokenKey(session.UserId, tokenId), 1,
            TimeSpan.FromMinutes(_jwtConfig.AccessTokenMinutesLifetime + 2));

        var newRefreshToken = await GenerateRefreshToken(session);

        var newAccessToken = await GenerateAccessToken(session.UserId, session.CredentialId);

        return (newAccessToken, newRefreshToken);
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

    private string GetAccessToken()
    {
        return httpContextAccessor.HttpContext!.Request.Headers["Authorization"].ToString()
            .Replace("Bearer ", string.Empty);
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

    public Task<string> GenerateAccessToken(SnowflakeId userId, SnowflakeId identityId)
    {
        return Task.FromResult<string>(ApiActivitySource.Instance.WithActivity((_) =>
            GenerateAsymmetricToken(userId, identityId, TimeSpan.FromMinutes(_jwtConfig.AccessTokenMinutesLifetime))));
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

    private string GenerateRefreshToken(SnowflakeId userId, SnowflakeId identityId, string sessionSecret)
    {
        return ApiActivitySource.Instance.WithActivity((_) =>
            GenerateSymmetricToken(userId, identityId, sessionSecret,
                TimeSpan.FromMinutes(_jwtConfig.AccessTokenMinutesLifetime)));
    }

    private string GenerateSymmetricToken(SnowflakeId userId, SnowflakeId identityId, string secret, TimeSpan lifetime)
    {
        var now = utcNow();
        var claims = new[]
        {
            new Claim(JwtRegisteredClaimNames.Sub, userId.ToString()),
            new Claim(CustomJwtClaimsNames.CredentialId, identityId.ToString()),
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

    private string GenerateAsymmetricToken(SnowflakeId userId, SnowflakeId credentialId, TimeSpan lifetime)
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
            new Claim(CustomJwtClaimsNames.CredentialId, credentialId.ToString()),
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