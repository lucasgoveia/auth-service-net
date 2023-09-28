using System.Data;
using AuthService.Common.Consts;
using AuthService.Common.Messaging;
using AuthService.Common.Results;
using AuthService.Common.Security;
using AuthService.Common.Timestamp;
using AuthService.WebApi.Common.Devices;
using AuthService.WebApi.Messages.Events;
using Dapper;

namespace AuthService.WebApi.Common.Auth;

public interface IAuthenticationService
{
    Task<Result<string>> LogIn(string username, string password, bool rememberMe, CancellationToken ct = default);
    Task LogOut(CancellationToken ct = default);
    Task LogOutAllSessions(CancellationToken ct);
    Task AuthenticateLimited(long userId, long identityId, CancellationToken ct = default);

    Task<string> Authenticate(long userId, long identityId, bool rememberMe,
        CancellationToken ct = default);
}

public class AuthenticationService : IAuthenticationService
{
    private readonly IIdentityForLoginGetter _identityForLoginGetter;
    private readonly IPasswordHasher _passwordHasher;
    private readonly IDeviceIdentifier _deviceIdentifier;
    private readonly ISessionManager _sessionManager;
    private readonly ITokenManager _tokenManager;
    private readonly IMessageBus _messageBus;
    private readonly UtcNow _utcNow;

    public AuthenticationService(
        IIdentityForLoginGetter identityForLoginGetter,
        IPasswordHasher passwordHasher,
        IDeviceIdentifier deviceIdentifier,
        ISessionManager sessionManager,
        ITokenManager tokenManager, IMessageBus messageBus, UtcNow utcNow)
    {
        _identityForLoginGetter = identityForLoginGetter;
        _passwordHasher = passwordHasher;
        _deviceIdentifier = deviceIdentifier;
        _sessionManager = sessionManager;
        _tokenManager = tokenManager;
        _messageBus = messageBus;
        _utcNow = utcNow;
    }
    
    public async Task AuthenticateLimited(long userId, long identityId, CancellationToken ct = default)
    {
        var device = _deviceIdentifier.Identify();
        var session = await _sessionManager.CreateLimitedSession(userId, identityId, device);

        _tokenManager.GenerateAndSetLimitedAccessToken(userId, identityId, session.SessionSecret, TimeSpan.FromMinutes(15));
    }

    public async Task<string> Authenticate(long userId, long identityId, bool rememberMe,
        CancellationToken ct = default)
    {
        var device = _deviceIdentifier.Identify();
        await _sessionManager.CreateSession(userId, identityId, device, rememberMe);

        await _tokenManager.GenerateAndSetRefreshToken();

        var accessToken = _tokenManager.GenerateAccessToken(userId, identityId);

        return accessToken;
    }

    public async Task<Result<string>> LogIn(string username, string password, bool rememberMe,
        CancellationToken ct = default)
    {
        var identity = await _identityForLoginGetter.Get(username, _utcNow(), ct);

        if (identity is null)
            return ErrorResult.Unauthorized();

        var correctCredentials = _passwordHasher.Verify(password, identity.PasswordHash);

        if (!correctCredentials)
        {
            await _messageBus.Publish(new LoginAttemptFailed { UserId = identity.UserId }, ct);
            return ErrorResult.Unauthorized();
        }

        var accessToken = await Authenticate(identity.UserId, identity.Id, rememberMe, ct);

        await _messageBus.Publish(new LoginAttemptSucceed { UserId = identity.UserId }, ct);
        return SuccessResult.Success(accessToken);
    }


    public async Task LogOut(CancellationToken ct = default)
    {
        await _tokenManager.RemoveRefreshToken();
        await _tokenManager.RevokeAccessToken();
        await _sessionManager.TerminateSession();
    }

    public async Task LogOutAllSessions(CancellationToken ct)
    {
        await _sessionManager.TerminateAllSessions();
    }
}

public record IdentityForLogin
{
    public required long Id { get; init; }
    public required long UserId { get; init; }
    public required string PasswordHash { get; init; }
}

public interface IIdentityForLoginGetter
{
    Task<IdentityForLogin?> Get(string username, DateTime now, CancellationToken ct = default);
}

public class IdentityForLoginGetter : IIdentityForLoginGetter
{
    private readonly IDbConnection _dbConnection;

    public IdentityForLoginGetter(IDbConnection dbConnection)
    {
        _dbConnection = dbConnection;
    }

    public async Task<IdentityForLogin?> Get(string username, DateTime now, CancellationToken ct = default)
    {
        return await _dbConnection.QuerySingleOrDefaultAsync<IdentityForLogin>(
            $@"SELECT i.id, i.user_id, i.password_hash 
                FROM {TableNames.Identities} i
                INNER JOIN {TableNames.Users} u ON i.user_id = u.id
                WHERE LOWER(i.username) = @Username AND u.deleted_at IS NULL 
                    AND i.deleted_at IS NULL 
                    AND (u.lockout_end_date IS NULL OR u.lockout_end_date < @Now)",
            new { Username = username.ToLower(), Now = now });
    }
}