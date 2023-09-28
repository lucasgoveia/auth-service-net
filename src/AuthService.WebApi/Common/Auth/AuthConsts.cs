namespace AuthService.WebApi.Common.Auth;

public static class CustomJwtClaimsNames
{
    public const string IdentityId = "identityId";
    public const string LimitedSession = "limitedSession";
}

public static class AuthCookieNames
{
    public const string SessionId = "Session-Id";
    public const string RefreshTokenCookieName = "Refresh-Token";
    public const string LimitedAccessToken = "Limited-Access-Token";
}