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
    public required string OrchestrationId { get; init; } = null!;
    public required SnowflakeId UserId { get; init; }
    public required SnowflakeId CredentialId { get; init; }
    public required string IpAddress { get; init; } = null!;
    public required string UserAgent { get; init; } = null!;
    public required bool TrustedDevice { get; init; }
    public required string DeviceFingerprint { get; init; } = null!;
    public required DateTime CreatedAt { get; init; }
    public required string SessionSecret { get; init; }
    public DateTime? ExpiresAt { get; init; }
}

public interface ISessionManager
{
    SnowflakeId? IdentityId { get; }
    SnowflakeId? UserId { get; }
    string? SessionId { get; }

    Task<Session> CreateSession(SnowflakeId userId, SnowflakeId identityId, DeviceDto device, bool trustedDevice, TimeSpan lifetime);
    Task<Session?> GetActiveSession();
    Task TerminateSession();
    Task TerminateAllSessions();
    Task SetActiveSessionByOrchestrationId(string orchestrationId);
    Task SetActiveSessionById(string sessionId);
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
        var identityId = _httpContextAccessor.HttpContext?.User.FindFirstValue(CustomJwtClaimsNames.CredentialId);

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
    
    public async Task<Session> CreateSession(SnowflakeId userId, SnowflakeId identityId, DeviceDto device, bool trustedDevice, TimeSpan lifetime)
    {
        _logger.LogInformation("creating session for user {userId} with IP {device.IpAddress}", userId, device.IpAddress);
        return await ApiActivitySource.Instance.WithActivity(async activity =>
        {
            var sessionId = _keyGenerator.Generate(SessionIdAlphabet, SessionIdLength);
            var orchestrationId = _keyGenerator.Generate(SessionIdAlphabet, SessionIdLength);

            var now = _utcNow();

            _session = new Session
            {
                SessionId = sessionId,
                OrchestrationId = orchestrationId,
                UserId = userId,
                CredentialId = identityId,
                IpAddress = device.IpAddress,
                UserAgent = device.UserAgent,
                TrustedDevice = trustedDevice,
                DeviceFingerprint = device.Fingerprint,
                CreatedAt = now,
                SessionSecret = GenerateJwtKey(),
                ExpiresAt = now.Add(lifetime)
            };

            _httpContextAccessor.HttpContext?.Response.Cookies.Append(AuthCookieNames.SessionId, sessionId,
                new CookieOptions
                {
                    Secure = true,
                    Path = "/",
                    HttpOnly = true,
                    Expires = _session.ExpiresAt,
                    MaxAge = lifetime,
                    SameSite = SameSiteMode.Strict
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
            SameSite = SameSiteMode.Strict
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
    
    public async Task SetActiveSessionByOrchestrationId(string orchestrationId)
    {
        _session = await _sessionRepository.GetByOrchestration(orchestrationId);
    }

    public async Task SetActiveSessionById(string sessionId)
    {
        SessionId = sessionId;
        _session = await _sessionRepository.Get(sessionId);
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
    Task<Session?> GetByOrchestration(string orchestrationId);
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
                (session_id, user_id, credential_id, ip_address, user_agent, device_fingerprint, created_at, session_secret) 
                VALUES (@SessionId, @UserId, @CredentialId, @IpAddress, @UserAgent, @DeviceFingerprint, @CreatedAt, @SessionSecret)",
            session);
    }

    public async Task<Session?> Get(string sessionId)
    {
        var session = await dbConnection.QuerySingleOrDefaultAsync<Session>(
            @$"SELECT * FROM {TableNames.UserSessions} WHERE session_id = @sessionId AND expires_at IS NULL",
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
            @$"UPDATE {TableNames.UserSessions} SET expires_at = @now WHERE session_id = @sessionId AND expires_at IS NULL",
            new { sessionId, now });
    }

    public async Task DeleteUserSessions(SnowflakeId userId, DateTime now)
    {
        await dbConnection.ExecuteAsync(
            @$"UPDATE {TableNames.UserSessions} SET expires_at = @now WHERE user_id = @userId AND expires_at IS NULL",
            new { userId, now });
    }

    public Task<Session?> GetByOrchestration(string orchestrationId)
    {
        return dbConnection.QuerySingleOrDefaultAsync<Session>(
            @$"SELECT * FROM {TableNames.UserSessions} WHERE orchestration_id = @orchestrationId AND expires_at IS NULL",
            new { orchestrationId });
    }
}