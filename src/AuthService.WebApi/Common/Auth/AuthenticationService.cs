using System.Data;
using System.Diagnostics;
using AuthService.Common;
using AuthService.Common.Consts;
using AuthService.Common.Messaging;
using AuthService.Common.Security;
using AuthService.Common.Timestamp;
using AuthService.WebApi.Common.Devices;
using AuthService.WebApi.Messages.Events;
using Dapper;
using LucasGoveia.Results;
using LucasGoveia.SnowflakeId;

namespace AuthService.WebApi.Common.Auth;

public interface IAuthenticationService
{
    Task<Result<string>> LogIn(string username, string password, bool rememberMe, CancellationToken ct = default);
    Task LogOut(CancellationToken ct = default);
    Task LogOutAllSessions(CancellationToken ct);

    Task<string> Authenticate(SnowflakeId userId, SnowflakeId identityId, bool rememberMe,
        CancellationToken ct = default);
}

public class AuthenticationService(
    IIdentityForLoginGetter identityForLoginGetter,
    IPasswordHasher passwordHasher,
    IDeviceIdentifier deviceIdentifier,
    ISessionManager sessionManager,
    ITokenManager tokenManager,
    IMessageBus messageBus,
    UtcNow utcNow,
    ILogger<AuthenticationService> logger)
    : IAuthenticationService
{
    public async Task<string> Authenticate(SnowflakeId userId, SnowflakeId identityId, bool rememberMe,
        CancellationToken ct = default)
    {
        return await ApiActivitySource.Instance.WithActivity(async actity =>
        {
            var device = deviceIdentifier.Identify();
            actity?.AddTag("device.fingerprint", device.Fingerprint);
            actity?.AddTag("device.ip", device.IpAddress);

            await sessionManager.CreateSession(userId, identityId, device, rememberMe);
            actity?.AddEvent(new ActivityEvent("SessionCreated", utcNow()));

            await tokenManager.GenerateAndSetRefreshToken();
            actity?.AddEvent(new ActivityEvent("RefreshTokenGenerated", utcNow()));

            var accessToken = tokenManager.GenerateAccessToken(userId, identityId);
            actity?.AddEvent(new ActivityEvent("AccessTokenGenerated", utcNow()));

            return accessToken;
        });
    }

    public async Task<Result<string>> LogIn(string username, string password, bool rememberMe,
        CancellationToken ct = default)
    {
        return await ApiActivitySource.Instance.WithActivity<Result<string>>(async (activity) =>
        {
            activity?.AddTag("username", username);
            logger.LogInformation("user {username} is logging in with rememberMe: {rememberMe}", username, rememberMe);
            var identity = await identityForLoginGetter.Get(username, utcNow(), ct);

            if (identity is null)
                return Result.Unauthorized();


            var correctCredentials = ApiActivitySource.Instance.WithActivity(
                (_) => passwordHasher.Verify(password, identity.PasswordHash),
                "PasswordVerification");

            if (!correctCredentials)
            {
                activity?.AddEvent(new ActivityEvent("LoginAttemptFailed", utcNow()));
                logger.LogInformation("{username} login attempt failed", username);
                await messageBus.Publish(new LoginAttemptFailed { UserId = identity.UserId }, ct);
                return Result.Unauthorized();
            }

            activity?.AddEvent(new ActivityEvent("LoginAttemptSuccess", utcNow()));
            var accessToken = await Authenticate(identity.UserId, identity.Id, rememberMe, ct);
            logger.LogInformation("{username} login attempt succeed", username);

            await messageBus.Publish(new LoginAttemptSucceed { UserId = identity.UserId }, ct);
            return Result.Ok(accessToken);
        });
    }


    public async Task LogOut(CancellationToken ct = default)
    {
        await tokenManager.RemoveRefreshToken();
        await tokenManager.RevokeAccessToken();
        await sessionManager.TerminateSession();
        logger.LogInformation("user logged out");
    }

    public async Task LogOutAllSessions(CancellationToken ct)
    {
        await tokenManager.RevokeUserAccessTokens(sessionManager.UserId!.Value);
        await sessionManager.TerminateAllSessions();
        logger.LogInformation("user logged out of all sessions");
    }
}

public record IdentityForLogin
{
    public required SnowflakeId Id { get; init; }
    public required SnowflakeId UserId { get; init; }
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