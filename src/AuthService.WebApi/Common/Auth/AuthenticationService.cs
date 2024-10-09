using System.Diagnostics;
using AuthService.Common;
using AuthService.Common.Timestamp;
using AuthService.WebApi.Common.Devices;
using LucasGoveia.SnowflakeId;

namespace AuthService.WebApi.Common.Auth;

public interface IAuthenticationService
{
    Task LogOut(CancellationToken ct = default);
    Task LogOutAllSessions(CancellationToken ct);

    Task<(string accessToken, string refreshToken)> Authenticate(SnowflakeId userId, SnowflakeId identityId, bool rememberMe,
        CancellationToken ct = default);
}

public class AuthenticationService(
    IDeviceIdentifier deviceIdentifier,
    ISessionManager sessionManager,
    ITokenManager tokenManager,
    UtcNow utcNow,
    ILogger<AuthenticationService> logger)
    : IAuthenticationService
{
    public async Task<(string accessToken, string refreshToken)> Authenticate(SnowflakeId userId, SnowflakeId identityId, bool rememberMe,
        CancellationToken ct = default)
    {
        return await ApiActivitySource.Instance.WithActivity(async actity =>
        {
            var device = deviceIdentifier.Identify();
            actity?.AddTag("device.fingerprint", device.Fingerprint);
            actity?.AddTag("device.ip", device.IpAddress);

            await sessionManager.CreateSession(userId, identityId, device, rememberMe);
            actity?.AddEvent(new ActivityEvent("SessionCreated", utcNow()));

            var refreshToken = await tokenManager.GenerateRefreshToken();
            actity?.AddEvent(new ActivityEvent("RefreshTokenGenerated", utcNow()));

            var accessToken = await tokenManager.GenerateAccessToken(userId, identityId);
            actity?.AddEvent(new ActivityEvent("AccessTokenGenerated", utcNow()));

            return (accessToken, refreshToken);
        });
    }
    

    public async Task LogOut(CancellationToken ct = default)
    {
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
