using AuthService.WebApi.Common.Auth;
using AuthService.WebApi.Common.Auth.Requirements;
using AuthService.WebApi.Common.Devices;
using Microsoft.AspNetCore.Authorization;

namespace AuthService.WebApi.Configurations;

public static class AuthConfiguration
{
    public static void AddAuthSetup(this WebApplicationBuilder builder)
    {
        builder.Services.Configure<JwtConfig>(builder.Configuration.GetSection("JwtConfiguration"));
        builder.Services.AddScoped<IAuthenticationService, AuthenticationService>();
        builder.Services.AddScoped<IIdentityForLoginGetter, IdentityForLoginGetter>();
        builder.Services.AddScoped<IDeviceIdentifier, DeviceIdentifier>();

        builder.Services.AddScoped<ISessionManager, SessionManager>();
        builder.Services.AddScoped<ITokenManager, TokenManager>();

        builder.Services
            .AddAuthentication(CustomJwtAuthentication.Scheme)
            .AddScheme<CustomJwtAuthenticationOptions, CustomJwtAuthenticationHandler>(CustomJwtAuthentication.Scheme,
                null)
            .AddScheme<RefreshTokenAuthenticationOptions, RefreshTokenAuthenticationHandler>(
                RefreshTokenAuthentication.Scheme, null)
            .AddScheme<ResetPasswordJwtAuthenticationOptions, ResetPasswordJwtAuthenticationHandler>(
                ResetPasswordJwtAuthentication.Scheme, null);

        builder.Services
            .AddAuthorization(options =>
            {
                options.InvokeHandlersAfterFailure = false;
                options.DefaultPolicy = new AuthorizationPolicyBuilder()
                    .RequireAuthenticatedUser()
                    .Build();
            });

        builder.Services.AddScoped<IAuthorizationHandler, NotAuthenticatedHandler>();
    }
}