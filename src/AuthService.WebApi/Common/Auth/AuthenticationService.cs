using System.Data;
using System.IdentityModel.Tokens.Jwt;
using System.Runtime.CompilerServices;
using System.Security.Claims;
using System.Text;
using AuthService.WebApi.Common.Caching;
using AuthService.WebApi.Common.Consts;
using AuthService.WebApi.Common.Devices;
using AuthService.WebApi.Common.Results;
using AuthService.WebApi.Common.Security;
using AuthService.WebApi.Common.Timestamp;
using Dapper;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

namespace AuthService.WebApi.Common.Auth;

public interface IAuthenticationService
{
    Task<Result<string>> LogIn(string username, string password, bool rememberMe, CancellationToken ct = default);
    Task<string> Authenticate(long identityId, bool rememberMe, CancellationToken ct = default);
    Task LogOut(CancellationToken ct = default);
    Task<Result<string>> RefreshToken(CancellationToken ct = default);
    Task<bool> IsAccessTokenRevoked(string accessToken, CancellationToken ct = default);
}

public record JwtConfig
{
    public required string AccessTokenSecret { get; init; }
    public required string RefreshTokenSecret { get; init; }
    public required int AccessTokenMinutesLifetime { get; init; }
    public required int RefreshTokenHoursLifetime { get; init; }
    public required int RefreshTokenInTrustedDevicesHoursLifetime { get; init; }
    public required int RefreshTokenAllowedRenewsCount { get; init; }
    public required string Issuer { get; init; }
}

public record RefreshTokenInfo
{
    public int UsageCount { get; init; }
    public bool TrustedDevice { get; init; }
}

public class AuthenticationService : IAuthenticationService
{
    private readonly JwtConfig _jwtConfig;
    private readonly IIdentityForLoginGetter _identityForLoginGetter;
    private readonly IPasswordHasher _passwordHasher;
    private readonly IHttpContextAccessor _httpContextAccessor;
    private readonly ICacher _cacher;
    private readonly IDeviceIdentifier _deviceIdentifier;
    private readonly IIdentityDeviceRepository _identityDeviceRepository;
    private readonly UtcNow _utcNow;

    public const string RefreshTokenCookieName = "refresh-token";

    public AuthenticationService(IOptions<JwtConfig> jwtOptions, IIdentityForLoginGetter identityForLoginGetter,
        IPasswordHasher passwordHasher, IHttpContextAccessor httpContextAccessor, ICacher cacher,
        IIdentityDeviceRepository identityDeviceRepository,
        IDeviceIdentifier deviceIdentifier, UtcNow utcNow)
    {
        _identityForLoginGetter = identityForLoginGetter;
        _passwordHasher = passwordHasher;
        _httpContextAccessor = httpContextAccessor;
        _cacher = cacher;
        _identityDeviceRepository = identityDeviceRepository;
        _deviceIdentifier = deviceIdentifier;
        _utcNow = utcNow;
        _jwtConfig = jwtOptions.Value;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static string BuildRefreshTokenKey(string deviceId, string refreshToken) =>
        $"accounts:sessions:{deviceId}:refresh-token:{refreshToken}";

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static string BuildRevokedAccessTokenKey(string accessToken) =>
        $"accounts:revoked-access-tokens:{accessToken}";

    public async Task<string> Authenticate(long identityId, bool rememberMe, CancellationToken ct = default)
    {
        var refreshTokenLifetime = GetRefreshTokenLifetime(rememberMe);

        var accessToken = GenerateAccessToken(identityId);

        var device = _deviceIdentifier.Identify();

        await GenerateAndSetRefreshToken(rememberMe, identityId, device.Fingerprint, refreshTokenLifetime);

        if (rememberMe)
        {
            await _identityDeviceRepository.Add(new IdentityDevice
            {
                Name = device.UserAgent,
                DeviceFingerprint = device.Fingerprint,
                IdentityId = identityId,
                IpAddress = device.IpAddress,
            });
        }

        return accessToken;
    }

    private TimeSpan GetRefreshTokenLifetime(bool trustedDevice)
    {
        var refreshTokenLifetime = trustedDevice
            ? TimeSpan.FromHours(_jwtConfig.RefreshTokenInTrustedDevicesHoursLifetime)
            : TimeSpan.FromHours(_jwtConfig.RefreshTokenHoursLifetime);
        return refreshTokenLifetime;
    }

    private async Task GenerateAndSetRefreshToken(bool trustedDevice, long identityId, string deviceFingerprint,
        TimeSpan expiration)
    {
        var refreshToken = GenerateRefreshToken(identityId, expiration);

        await _cacher.Set(
            BuildRefreshTokenKey(deviceFingerprint, refreshToken),
            new RefreshTokenInfo { TrustedDevice = trustedDevice, UsageCount = 0 },
            expiration
        );

        _httpContextAccessor.HttpContext!.Response.Cookies.Append(RefreshTokenCookieName, refreshToken,
            new CookieOptions
            {
                Secure = true,
                Path = "/",
                HttpOnly = true,
                Expires = _utcNow().Add(expiration),
                MaxAge = expiration
            });
    }

    public async Task<Result<string>> LogIn(string username, string password, bool rememberMe,
        CancellationToken ct = default)
    {
        var user = await _identityForLoginGetter.Get(username, ct);

        if (user is null)
            return ErrorResult.Unauthorized();

        var correctCredentials = _passwordHasher.Verify(password, user.PasswordHash);

        if (!correctCredentials)
        {
            return ErrorResult.Unauthorized();
        }

        var accessToken = await Authenticate(user.Id, rememberMe, ct);

        return SuccessResult.Success(accessToken);
    }


    public async Task LogOut(CancellationToken ct = default)
    {
        var device = _deviceIdentifier.Identify();
        var refreshToken = _httpContextAccessor.HttpContext!.Request.Cookies[RefreshTokenCookieName];
        var accessToken = _httpContextAccessor.HttpContext!.Request.Headers.Authorization.ToString().Split(" ")[1];

        if (!string.IsNullOrEmpty(refreshToken))
        {
            await _cacher.Remove(BuildRefreshTokenKey(device.Fingerprint, refreshToken));
            _httpContextAccessor.HttpContext!.Response.Cookies.Delete(RefreshTokenCookieName);
        }

        await _identityDeviceRepository.Remove(device.Fingerprint);

        await _cacher.Set(BuildRevokedAccessTokenKey(accessToken), true,
            TimeSpan.FromMinutes(_jwtConfig.AccessTokenMinutesLifetime));
    }

    public async Task<bool> AllowTokenRefresh(string deviceFingerprint, long identityId,
        RefreshTokenInfo? refreshTokenInfo)
    {
        var storedDevice = await _identityDeviceRepository.Get(deviceFingerprint);

        if (storedDevice is null || storedDevice.IdentityId != identityId)
        {
            return false;
        }

        if (refreshTokenInfo is null)
        {
            return false;
        }

        if (refreshTokenInfo.UsageCount + 1 > _jwtConfig.RefreshTokenAllowedRenewsCount)
        {
            return false;
        }

        return true;
    }

    public async Task<Result<string>> RefreshToken(CancellationToken ct = default)
    {
        var device = _deviceIdentifier.Identify();
        var refreshToken = _httpContextAccessor.HttpContext!.Request.Cookies[RefreshTokenCookieName];

        if (string.IsNullOrEmpty(refreshToken))
        {
            return ErrorResult.Unauthorized();
        }

        var (info, expiry) =
            await _cacher.GetWithExpiration<RefreshTokenInfo>(BuildRefreshTokenKey(device.Fingerprint, refreshToken));

        var identityId = GetIdentityIdFromToken(refreshToken);

        if (!await AllowTokenRefresh(device.Fingerprint, identityId, info))
        {
            await RemoveRefreshToken(device, refreshToken);
            return ErrorResult.Unauthorized();
        }

        if (info!.UsageCount + 1 == _jwtConfig.RefreshTokenAllowedRenewsCount)
        {
            var newExpiration = info.TrustedDevice
                ? TimeSpan.FromHours(_jwtConfig.RefreshTokenInTrustedDevicesHoursLifetime)
                : expiry.GetValueOrDefault();

            await GenerateAndSetRefreshToken(true, identityId, device.Fingerprint, newExpiration);

            return SuccessResult.Success(GenerateAccessTokenFromRefreshToken(refreshToken));
        }

        await _cacher.Set(BuildRefreshTokenKey(device.Fingerprint, refreshToken),
            info with { UsageCount = info.UsageCount + 1 },
            expiry);

        return SuccessResult.Success(GenerateAccessTokenFromRefreshToken(refreshToken));
    }

    private async Task RemoveRefreshToken(DeviceDto device, string refreshToken)
    {
        _httpContextAccessor.HttpContext!.Response.Cookies.Delete(RefreshTokenCookieName);
        await _cacher.Remove(BuildRefreshTokenKey(device.Fingerprint, refreshToken));
    }

    public async Task<bool> IsAccessTokenRevoked(string accessToken, CancellationToken ct = default)
    {
        return await _cacher.Get<bool?>(BuildRevokedAccessTokenKey(accessToken)) ?? false;
    }

    private string GenerateRefreshToken(long identityId, TimeSpan lifetime)
    {
        return GenerateToken(identityId, _jwtConfig.RefreshTokenSecret, lifetime);
    }

    private string GenerateAccessToken(long identityId)
    {
        return GenerateToken(identityId, _jwtConfig.AccessTokenSecret,
            TimeSpan.FromMinutes(_jwtConfig.AccessTokenMinutesLifetime));
    }

    private long GetIdentityIdFromToken(string token)
    {
        var handler = new JwtSecurityTokenHandler();
        var jwtSecurityToken = handler.ReadJwtToken(token);
        return long.Parse(jwtSecurityToken.Subject);
    }

    private string GenerateAccessTokenFromRefreshToken(string refreshToken)
    {
        var identityId = GetIdentityIdFromToken(refreshToken);

        return GenerateAccessToken(identityId);
    }

    private string GenerateToken(long identityId, string secret, TimeSpan lifetime)
    {
        var now = _utcNow();
        var claims = new[]
        {
            new Claim(JwtRegisteredClaimNames.Sub, identityId.ToString()),
            new Claim(JwtRegisteredClaimNames.Iat, EpochTime.GetIntDate(now).ToString(), ClaimValueTypes.Integer64)
        };

        var expiry = _utcNow().Add(lifetime);
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
}

public record IdentityForLogin
{
    public required long Id { get; init; }
    public required string PasswordHash { get; init; }
}

public interface IIdentityForLoginGetter
{
    Task<IdentityForLogin?> Get(string username, CancellationToken ct = default);
    Task<IdentityForLogin?> Get(long identityId, CancellationToken ct = default);
}

public class IdentityForLoginGetter : IIdentityForLoginGetter
{
    private readonly IDbConnection _dbConnection;

    public IdentityForLoginGetter(IDbConnection dbConnection)
    {
        _dbConnection = dbConnection;
    }

    public async Task<IdentityForLogin?> Get(string username, CancellationToken ct = default)
    {
        return await _dbConnection.QuerySingleOrDefaultAsync<IdentityForLogin?>(
            $"SELECT id, password_hash FROM {TableNames.Identities} WHERE LOWER(username) = @Username",
            new { Username = username.ToLower() });
    }

    public async Task<IdentityForLogin?> Get(long identityId, CancellationToken ct = default)
    {
        return await _dbConnection.QuerySingleOrDefaultAsync<IdentityForLogin?>(
            $"SELECT id, password_hash FROM {TableNames.Identities} WHERE id = @identityId",
            new { identityId });
    }
}