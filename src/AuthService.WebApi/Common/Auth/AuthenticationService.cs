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
    Task<string> Authenticate(long userId, long identityId, bool rememberMe,
        CancellationToken ct = default);
}

public class AuthenticationService(IIdentityForLoginGetter identityForLoginGetter,
        IPasswordHasher passwordHasher,
        IDeviceIdentifier deviceIdentifier,
        ISessionManager sessionManager,
        ITokenManager tokenManager, IMessageBus messageBus, UtcNow utcNow)
    : IAuthenticationService
{

    public async Task<string> Authenticate(long userId, long identityId, bool rememberMe,
        CancellationToken ct = default)
    {
        var device = deviceIdentifier.Identify();
        await sessionManager.CreateSession(userId, identityId, device, rememberMe);

        await tokenManager.GenerateAndSetRefreshToken();

        var accessToken = tokenManager.GenerateAccessToken(userId, identityId);

        return accessToken;
    }

    public async Task<Result<string>> LogIn(string username, string password, bool rememberMe,
        CancellationToken ct = default)
    {
        var identity = await identityForLoginGetter.Get(username, utcNow(), ct);

        if (identity is null)
            return ErrorResult.Unauthorized();

        var correctCredentials = passwordHasher.Verify(password, identity.PasswordHash);

        if (!correctCredentials)
        {
            await messageBus.Publish(new LoginAttemptFailed { UserId = identity.UserId }, ct);
            return ErrorResult.Unauthorized();
        }

        var accessToken = await Authenticate(identity.UserId, identity.Id, rememberMe, ct);

        await messageBus.Publish(new LoginAttemptSucceed { UserId = identity.UserId }, ct);
        return SuccessResult.Success(accessToken);
    }


    public async Task LogOut(CancellationToken ct = default)
    {
        await tokenManager.RemoveRefreshToken();
        await tokenManager.RevokeAccessToken();
        await sessionManager.TerminateSession();
    }

    public async Task LogOutAllSessions(CancellationToken ct)
    {
        await tokenManager.RevokeUserAccessTokens(sessionManager.UserId!.Value);
        await sessionManager.TerminateAllSessions();
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

public class IdentityForLoginGetter(IDbConnection dbConnection) : IIdentityForLoginGetter
{
    public async Task<IdentityForLogin?> Get(string username, DateTime now, CancellationToken ct = default)
    {
        return await dbConnection.QuerySingleOrDefaultAsync<IdentityForLogin>(
            $@"SELECT i.id, i.user_id, i.password_hash 
                FROM {TableNames.Identities} i
                INNER JOIN {TableNames.Users} u ON i.user_id = u.id
                WHERE LOWER(i.username) = @Username AND u.deleted_at IS NULL 
                    AND i.deleted_at IS NULL 
                    AND (u.lockout_end_date IS NULL OR u.lockout_end_date < @Now)",
            new { Username = username.ToLower(), Now = now });
    }
}