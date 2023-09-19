using System.Data;
using System.IdentityModel.Tokens.Jwt;
using System.Runtime.CompilerServices;
using System.Security.Claims;
using System.Text;
using AuthService.WebApi.Common.Caching;
using AuthService.WebApi.Common.Consts;
using AuthService.WebApi.Common.Result;
using AuthService.WebApi.Common.Security;
using Dapper;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

namespace AuthService.WebApi.Common.Auth;

public interface IAuthenticationService
{
    Task<Result<string>> LogIn(string username, string password, CancellationToken ct = default);

    Task<string> Authenticate(long identityId, CancellationToken ct = default);
    Task LogOut(CancellationToken ct = default);

    Task<Result<string>> RefreshToken(CancellationToken ct = default);
}

public record JwtConfig
{
    public required string AccessTokenSecret { get; init; }
    public required string RefreshTokenSecret { get; init; }
    public required int AccessTokenMinutesLifetime { get; init; }
    public required int RefreshTokenHoursLifetime { get; init; }
    public required string Issuer { get; init; }
}

public record RefreshTokenInfo
{
    public int UsageCount { get; init; }
    public bool AllowRenew { get; init; }
}

public class AuthenticationService : IAuthenticationService
{
    private readonly JwtConfig _jwtConfig;
    private readonly IIdentityForLoginGetter _identityForLoginGetter;
    private readonly IPasswordHasher _passwordHasher;
    private readonly IHttpContextAccessor _httpContextAccessor;
    private readonly ICacher _cacher;
    private readonly ILogger<AuthenticationService> _logger;
    private readonly IDeviceIdentifier _deviceIdentifier;
    private readonly IIdentityDeviceRepository _identityDeviceRepository;

    public const string RefreshTokenCookieName = "refresh-token";

    public AuthenticationService(IOptions<JwtConfig> jwtOptions, IIdentityForLoginGetter identityForLoginGetter,
        IPasswordHasher passwordHasher, IHttpContextAccessor httpContextAccessor, ICacher cacher,
        ILogger<AuthenticationService> logger, IIdentityDeviceRepository identityDeviceRepository,
        IDeviceIdentifier deviceIdentifier)
    {
        _identityForLoginGetter = identityForLoginGetter;
        _passwordHasher = passwordHasher;
        _httpContextAccessor = httpContextAccessor;
        _cacher = cacher;
        _logger = logger;
        _identityDeviceRepository = identityDeviceRepository;
        _deviceIdentifier = deviceIdentifier;
        _jwtConfig = jwtOptions.Value;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static string BuildRefreshTokenKey(string deviceId, string refreshToken) =>
        $"accounts:sessions:{deviceId}:refresh-token:{refreshToken}";
    
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static string BuildRevokedAccessTokenKey(string accessToken) =>
        $"accounts:revoked-tokens:{accessToken}";

    public async Task<string> Authenticate(long identityId, CancellationToken ct = default)
    {
        var accessToken = GenerateAccessToken(identityId);
        var refreshToken = GenerateRefreshToken(identityId);

        var device = _deviceIdentifier.Identify();

        await _cacher.Set(BuildRefreshTokenKey(device.Fingerprint, refreshToken),
            // will always allow renewing the token for now
            new RefreshTokenInfo { AllowRenew = true, UsageCount = 0 },
            TimeSpan.FromHours(_jwtConfig.RefreshTokenHoursLifetime));

        await _identityDeviceRepository.Add(new IdentityDevice
        {
            Name = device.UserAgent,
            DeviceFingerprint = device.Fingerprint,
            IdentityId = identityId,
            IpAddress = device.IpAddress,
        });

        _httpContextAccessor.HttpContext!.Response.Cookies.Append(RefreshTokenCookieName, refreshToken,
            new CookieOptions
            {
                Secure = true,
                Path = "/",
                HttpOnly = true,
                Expires = DateTimeOffset.UtcNow.AddHours(_jwtConfig.RefreshTokenHoursLifetime),
                MaxAge = TimeSpan.FromHours(_jwtConfig.RefreshTokenHoursLifetime)
            });

        return accessToken;
    }

    public async Task<Result<string>> LogIn(string username, string password, CancellationToken ct = default)
    {
        var user = await _identityForLoginGetter.Get(username, ct);

        if (user is null)
            return ErrorResult.Unauthorized();

        var correctCredentials = _passwordHasher.Verify(password, user.PasswordHash);

        if (!correctCredentials)
        {
            return ErrorResult.Unauthorized();
        }

        var accessToken = await Authenticate(user.Id, ct);

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
        
        await _cacher.Set(BuildRevokedAccessTokenKey(accessToken), true, TimeSpan.FromMinutes(_jwtConfig.AccessTokenMinutesLifetime));
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

        if (info is null)
        {
            _httpContextAccessor.HttpContext!.Response.Cookies.Delete(RefreshTokenCookieName);
            return ErrorResult.Unauthorized();
        }

        await _cacher.Set(BuildRefreshTokenKey(device.Fingerprint, refreshToken),
            info with { UsageCount = info.UsageCount + 1 },
            expiry);

        return SuccessResult.Success(GenerateAccessTokenFromRefreshToken(refreshToken));
    }

    private string GenerateRefreshToken(long identityId)
    {
        return GenerateToken(identityId, _jwtConfig.RefreshTokenSecret,
            TimeSpan.FromMinutes(_jwtConfig.RefreshTokenHoursLifetime));
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
        var claims = new[]
        {
            new Claim(JwtRegisteredClaimNames.Sub, identityId.ToString())
        };

        var expiry = DateTime.UtcNow.Add(lifetime);
        var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secret));
        var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);

        var token = new JwtSecurityToken(
            issuer: _jwtConfig.Issuer,
            audience: "localhost",
            claims: claims,
            expires: expiry,
            signingCredentials: credentials
        );

        return new JwtSecurityTokenHandler().WriteToken(token);
    }
}

public record IdentityForLogin
{
    public required long Id { get; init; }
    public required string Username { get; init; }
    public required string PasswordHash { get; init; }
}

public interface IIdentityForLoginGetter
{
    Task<IdentityForLogin?> Get(string username, CancellationToken ct = default);
}

public class IdentityForLoginGetter : IIdentityForLoginGetter
{
    private readonly IDbConnection _dbConnection;

    public IdentityForLoginGetter(IDbConnection dbConnection)
    {
        _dbConnection = dbConnection;
    }

    public Task<IdentityForLogin?> Get(string username, CancellationToken ct = default)
    {
        return _dbConnection.QuerySingleOrDefaultAsync<IdentityForLogin?>(
            $"SELECT id as Id, username as Username , password_hash as PasswordHash FROM {TableNames.Identities} WHERE LOWER(username) = @Username",
            new { Username = username.ToLower() });
    }
}