namespace AuthService.WebApi.Common.Auth;

public class AuthConfig
{
    public required int SessionTrustedDevicesLifetimeHours { get; init; } = 7 * 24;
    public required int SessionDefaultLifetimeHours { get; init; } = 24;
    public required string SessionCookieDomain { get; init; }
}