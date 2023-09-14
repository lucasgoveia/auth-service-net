using System.Data;
using System.IdentityModel.Tokens.Jwt;
using System.Runtime.CompilerServices;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using AuthService.WebApi.Common.Caching;
using AuthService.WebApi.Common.Result;
using AuthService.WebApi.Common.Security;
using Dapper;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

namespace AuthService.WebApi.Common.Auth;

public interface IAuthenticationService
{
    Task<Result<string>> LogIn(string username, string password, string fingerprint,
        CancellationToken ct = default);

    Task LogOut(CancellationToken ct = default);
}

public record JwtConfig
{
    public required string AccessTokenSecret { get; init; }
    public required string RefreshTokenSecret { get; init; }
    public required int AccessTokenMinutesLifetime { get; init; }
    public required int RefreshTokenHoursLifetime { get; init; }
    public required string Issuer { get; init; }
}

public class AuthenticationService : IAuthenticationService
{
    private readonly JwtConfig _jwtConfig;
    private readonly IUserForLoginGetter _userForLoginGetter;
    private readonly IPasswordHasher _passwordHasher;
    private readonly IHttpContextAccessor _httpContextAccessor;
    private readonly ICacher _cacher;
    private readonly ILogger<AuthenticationService> _logger;

    private const string RefreshTokenCookieName = "refresh-token";
    
    public AuthenticationService(IOptions<JwtConfig> jwtOptions, IUserForLoginGetter userForLoginGetter,
        IPasswordHasher passwordHasher, IHttpContextAccessor httpContextAccessor, ICacher cacher, ILogger<AuthenticationService> logger)
    {
        _userForLoginGetter = userForLoginGetter;
        _passwordHasher = passwordHasher;
        _httpContextAccessor = httpContextAccessor;
        _cacher = cacher;
        _logger = logger;
        _jwtConfig = jwtOptions.Value;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static string BuildRefreshTokenKey(string deviceId, string refreshToken) => $"accounts:sessions:{deviceId}:refresh-token:{refreshToken}";

    public async Task<Result<string>> LogIn(string username, string password,
        string fingerprint, CancellationToken ct = default)
    {
        var user = await _userForLoginGetter.Get(username, ct);

        if (user is null)
            return ErrorResult.Unauthorized();

        var correctCredentials = _passwordHasher.Verify(password, user.PasswordHash);

        if (!correctCredentials)
        {
            return ErrorResult.Unauthorized();
        }

        var accessToken = GenerateAccessToken(user);
        var refreshToken = GenerateRefreshToken(user);

        var deviceId = IdentityUserDevice(fingerprint);

        await _cacher.Set(BuildRefreshTokenKey(deviceId, refreshToken), 0,
            TimeSpan.FromHours(_jwtConfig.RefreshTokenHoursLifetime));
        
        _httpContextAccessor.HttpContext!.Response.Cookies.Append(RefreshTokenCookieName, refreshToken,
            new CookieOptions
            {
                Secure = true,
                Path = "/",
                HttpOnly = true,
                Expires = DateTimeOffset.UtcNow.AddHours(_jwtConfig.RefreshTokenHoursLifetime),
                MaxAge = TimeSpan.FromHours(_jwtConfig.RefreshTokenHoursLifetime)
            });

        return SuccessResult.Success(accessToken);
    }

    public Task LogOut(CancellationToken ct = default)
    {
        throw new NotImplementedException();
    }

    private string IdentityUserDevice(string fingerprint)
    {
        var userAgent = _httpContextAccessor.HttpContext?.Request.Headers["User-Agent"];
        var ipAddress = _httpContextAccessor.HttpContext?.Connection.RemoteIpAddress?.ToString();
        var unHashedDeviceId = $"{fingerprint}.{userAgent}.{ipAddress}";
        
        _logger.LogInformation("Unhashed device id: {UnHashedDeviceId}", unHashedDeviceId);
        
        using var algorithm = SHA256.Create();
        return algorithm.ComputeHash(Encoding.UTF8.GetBytes(unHashedDeviceId))
            .Aggregate(new StringBuilder(), (sb, nb) => sb.Append(nb.ToString("x2")))
            .ToString();
    }

    private string GenerateRefreshToken(UserForLogin user)
    {
        return GenerateToken(user, _jwtConfig.RefreshTokenSecret,
            TimeSpan.FromMinutes(_jwtConfig.RefreshTokenHoursLifetime));
    }

    private string GenerateAccessToken(UserForLogin user)
    {
        return GenerateToken(user, _jwtConfig.AccessTokenSecret,
            TimeSpan.FromMinutes(_jwtConfig.AccessTokenMinutesLifetime));
    }

    private string GenerateToken(UserForLogin user, string secret, TimeSpan lifetime)
    {
        var claims = new[]
        {
            new Claim(JwtRegisteredClaimNames.UniqueName, user.Username),
            new Claim(JwtRegisteredClaimNames.Sub, user.Id.ToString())
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

public record UserForLogin
{
    public required long Id { get; init; }
    public required string Username { get; init; }
    public required string PasswordHash { get; init; }
}

public interface IUserForLoginGetter
{
    Task<UserForLogin?> Get(string username, CancellationToken ct = default);
}

public class UserForLoginGetter : IUserForLoginGetter
{
    private readonly IDbConnection _dbConnection;

    public UserForLoginGetter(IDbConnection dbConnection)
    {
        _dbConnection = dbConnection;
    }

    public Task<UserForLogin?> Get(string username, CancellationToken ct = default)
    {
        return _dbConnection.QuerySingleOrDefaultAsync<UserForLogin?>(
            "SELECT id as Id, username as Username , password_hash as PasswordHash FROM iam.identity WHERE LOWER(username) = @Username",
            new { Username = username.ToLower() });
    }
}