namespace AuthService.WebApi.Common.Auth;

public static class CustomJwtClaimsNames
{
    public const string CredentialId = "credentialId";
}

public static class AuthCookieNames
{
    public const string SessionId = "Session-Id";
    public const string RefreshTokenCookieName = "Refresh-Token";
}