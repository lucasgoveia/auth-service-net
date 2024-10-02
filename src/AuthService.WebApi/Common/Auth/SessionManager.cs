using System.Data;
using System.Diagnostics;
using System.Globalization;
using System.Runtime.CompilerServices;
using System.Security.Claims;
using AuthService.Common;
using AuthService.Common.Caching;
using AuthService.Common.Consts;
using AuthService.Common.Security;
using AuthService.Common.Timestamp;
using AuthService.WebApi.Common.Devices;
using Dapper;
using LucasGoveia.SnowflakeId;
using Microsoft.Extensions.Options;

namespace AuthService.WebApi.Common.Auth;

public record Session
{
    public int Id { get; init; }
    public required string SessionId { get; init; } = null!;
    public required SnowflakeId UserId { get; init; }
    public required SnowflakeId IdentityId { get; init; }
    public required string IpAddress { get; init; } = null!;
    public required string UserAgent { get; init; } = null!;
    public required bool TrustedDevice { get; init; }
    public required string DeviceFingerprint { get; init; } = null!;
    public required DateTime CreatedAt { get; init; }
    public required string SessionSecret { get; init; }
    public DateTime? EndedAt { get; init; }
}

public interface ISessionManager
{
    SnowflakeId? IdentityId { get; }
    SnowflakeId? UserId { get; }
    string? SessionId { get; }

    Task<Session> CreateSession(SnowflakeId userId, SnowflakeId identityId, DeviceDto device, bool trustedDevice = false);
    Task<Session?> GetActiveSession();
    Task TerminateSession();
    Task TerminateAllSessions();
    Task AddSessionProperty<T>(string name, T value);
    Task<T?> GetSessionProperty<T>(string name);
}

public static class SessionPropertiesNames
{
    public const string VerifiedRecoveryCode = "verified_recovery_code";
}

public class SessionManager : ISessionManager
{
    private const int SessionIdLength = 32;
    private const int RefreshTokenJwtKeyLength = 64;

    private static readonly char[] SessionIdAlphabet =
        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789".ToCharArray();

    private static readonly char[] JwtKeyAlphabet =
        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+=@!#$%&*(){}[],.;:'`~".ToCharArray();

    private readonly ISecureKeyGenerator _keyGenerator;
    private readonly IHttpContextAccessor _httpContextAccessor;
    private readonly UtcNow _utcNow;
    private readonly ISessionRepository _sessionRepository;
    private Session? _session;
    private readonly ICacher _cacher;
    private readonly ILogger<SessionManager> _logger;

    private SnowflakeId? _userId;
    private SnowflakeId? _identityId;
    private string? _sessionId;

    public SnowflakeId? IdentityId
    {
        get => _identityId ?? GetIdentityId();
        set => _identityId = value;
    }

    public SnowflakeId? UserId
    {
        get => _userId ?? GetUserId();
        set => _userId = value;
    }

    private SnowflakeId? GetUserId()
    {
        var userId = _httpContextAccessor.HttpContext?.User.FindFirstValue(ClaimTypes.NameIdentifier);

        if (userId is null)
            return null;

        _userId = SnowflakeId.Parse(userId, CultureInfo.InvariantCulture);
        return _userId;
    }

    private SnowflakeId? GetIdentityId()
    {
        var identityId = _httpContextAccessor.HttpContext?.User.FindFirstValue(CustomJwtClaimsNames.IdentityId);

        if (identityId is null)
            return null;

        _identityId = SnowflakeId.Parse(identityId, CultureInfo.InvariantCulture);
        return _identityId;
    }

    public string? SessionId
    {
        get => _sessionId;
        set => _sessionId = value;
    }

    public SessionManager(ISecureKeyGenerator keyGenerator, IHttpContextAccessor httpContextAccessor,
        UtcNow utcNow, ISessionRepository sessionRepository, ICacher cacher, ILogger<SessionManager> logger)
    {
        _keyGenerator = keyGenerator;
        _httpContextAccessor = httpContextAccessor;
        _utcNow = utcNow;
        _sessionRepository = sessionRepository;
        _cacher = cacher;
        _logger = logger;

        if (httpContextAccessor.HttpContext?.Request.Cookies.TryGetValue(AuthCookieNames.SessionId,
                out var sessionId) ?? false)
        {
            SessionId = sessionId;
        }
    }
    
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static string BuildSessionPropKey(SnowflakeId userId, string sessionId, string propName) =>
        $"accounts:{userId}:sessions:{sessionId}:{propName}";
    
    public async Task AddSessionProperty<T>(string name, T value)
    {
        if (SessionId is null || !UserId.HasValue)
            throw new InvalidOperationException();

        await _cacher.Set(BuildSessionPropKey(UserId.Value, SessionId, name), value, TimeSpan.FromDays(30));
    }
    
    public async Task<T?> GetSessionProperty<T>(string name)
    {
        if (SessionId is null || !UserId.HasValue)
            throw new InvalidOperationException();

        return await _cacher.Get<T>(BuildSessionPropKey(UserId.Value, SessionId, name));
    }

    public async Task<Session> CreateSession(SnowflakeId userId, SnowflakeId identityId, DeviceDto device, bool trustedDevice = false)
    {
        _logger.LogInformation("creating session for user {userId} with IP {device.IpAddress}", userId, device.IpAddress);
        return await CreateSession(userId, identityId, device, trustedDevice, lifetime: null);
    }
    
    private async Task<Session> CreateSession(SnowflakeId userId, SnowflakeId identityId, DeviceDto device, bool trustedDevice, TimeSpan? lifetime)
    {
        return await ApiActivitySource.Instance.WithActivity(async activity =>
        {
            var sessionId = _keyGenerator.Generate(SessionIdAlphabet, SessionIdLength);

            var now = _utcNow();

            _session = new Session
            {
                SessionId = sessionId,
                UserId = userId,
                IdentityId = identityId,
                IpAddress = device.IpAddress,
                UserAgent = device.UserAgent,
                TrustedDevice = trustedDevice,
                DeviceFingerprint = device.Fingerprint,
                CreatedAt = now,
                SessionSecret = GenerateJwtKey(),
                EndedAt = lifetime.HasValue ? now.Add(lifetime.Value) : now.AddYears(10)
            };

            _httpContextAccessor.HttpContext?.Response.Cookies.Append(AuthCookieNames.SessionId, sessionId,
                new CookieOptions
                {
                    Secure = true,
                    Path = "/",
                    HttpOnly = true,
                    Expires = _session.EndedAt,
                    MaxAge = lifetime,
                    SameSite = SameSiteMode.None
                });
            activity?.AddEvent(new ActivityEvent("AddedSessionCookie", now));

            SessionId = sessionId;
            UserId = userId;
            IdentityId = identityId;

            await _sessionRepository.Add(_session);
            activity?.AddEvent(new ActivityEvent("SessionAddedToDb", now));

            return _session;
        });
    }

    public async Task<Session?> GetActiveSession()
    {
        if (_session is not null)
            return _session;

        if (SessionId is null)
            return null;

        _session = await _sessionRepository.Get(SessionId);

        return _session;
    }
    
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static string BuildUserSessionsPattern(SnowflakeId accountId) =>
        $"accounts:{accountId}:sessions:*";
    
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static string BuildSessionPattern(SnowflakeId accountId, string sessionId) =>
        $"accounts:{accountId}:sessions:{sessionId}:*";

    public async Task TerminateSession()
    {
        _logger.LogInformation("terminating session for user {userId}", UserId!.Value);
        
        if (SessionId is null)
            return;

        _httpContextAccessor.HttpContext?.Response.Cookies.Delete(AuthCookieNames.SessionId, new CookieOptions
        {
            Secure = true,
            Path = "/",
            HttpOnly = true,
            Expires = _utcNow().AddYears(-1),
            SameSite = SameSiteMode.None
        });
        await _sessionRepository.Delete(SessionId, _utcNow());
        await _cacher.ClearPattern(BuildSessionPattern(UserId!.Value, SessionId));
    }

    public async Task TerminateAllSessions()
    {
        _logger.LogInformation("terminating all sessions for user {userId}", UserId!.Value);
        
        if (UserId is null)
            return;

        await _sessionRepository.DeleteUserSessions(UserId.Value, _utcNow());
        await _cacher.ClearPattern(BuildUserSessionsPattern(UserId.Value));
    }

    private string GenerateJwtKey()
    {
        return _keyGenerator.Generate(JwtKeyAlphabet, RefreshTokenJwtKeyLength);
    }
}

public interface ISessionRepository
{
    Task Add(Session session);
    Task<Session?> Get(string sessionId);
    Task Delete(string sessionId, DateTime now);
    Task DeleteUserSessions(SnowflakeId userId, DateTime now);
}

public class SessionRepository(IDbConnection dbConnection, IAesEncryptor aesEncryptor, IOptions<JwtConfig> jwtConfig)
    : ISessionRepository
{
    private readonly string _refreshTokenSecret = jwtConfig.Value.RefreshTokenSecret;

    public async Task Add(Session session)
    {
        session = session with
        {
            SessionSecret =
            await aesEncryptor.Encrypt(session.SessionSecret, _refreshTokenSecret, session.SessionId)
        };

        await dbConnection.ExecuteAsync(
            @$"INSERT INTO {TableNames.UserSessions} 
                (session_id, user_id, identity_id, ip_address, user_agent, device_fingerprint, created_at, session_secret) 
                VALUES (@SessionId, @UserId, @IdentityId, @IpAddress, @UserAgent, @DeviceFingerprint, @CreatedAt, @SessionSecret)",
            session);
    }

    public async Task<Session?> Get(string sessionId)
    {
        var session = await dbConnection.QuerySingleOrDefaultAsync<Session>(
            @$"SELECT * FROM {TableNames.UserSessions} WHERE session_id = @sessionId AND ended_at IS NULL",
            new { sessionId });

        if (session is null)
            return null;

        return session with
        {
            SessionSecret =
            await aesEncryptor.Decrypt(session.SessionSecret, _refreshTokenSecret, session.SessionId)
        };
    }

    public async Task Delete(string sessionId, DateTime now)
    {
        await dbConnection.ExecuteAsync(
            @$"UPDATE {TableNames.UserSessions} SET ended_at = @now WHERE session_id = @sessionId AND ended_at IS NULL",
            new { sessionId, now });
    }

    public async Task DeleteUserSessions(SnowflakeId userId, DateTime now)
    {
        await dbConnection.ExecuteAsync(
            @$"UPDATE {TableNames.UserSessions} SET ended_at = @now WHERE user_id = @userId AND ended_at IS NULL",
            new { userId, now });
    }
}