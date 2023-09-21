using AuthService.WebApi.Common;
using AuthService.WebApi.Common.Auth;
using AuthService.WebApi.Common.Devices;
using Microsoft.AspNetCore.Authorization;

namespace AuthService.WebApi.Configurations;

public static class AuthConfiguration
{
    public static void AddAuthSetup(this WebApplicationBuilder builder)
    {
        builder.Services.Configure<JwtConfig>(builder.Configuration.GetSection("JwtConfiguration"));
        builder.Services.AddScoped<IAuthenticationService, AuthenticationService>();
        builder.Services.AddTransient<IIdentityForLoginGetter, IdentityForLoginGetter>();
        builder.Services.AddTransient<IIdentityDeviceRepository, IdentityDeviceRepository>();
        builder.Services.AddScoped<IDeviceIdentifier, DeviceIdentifier>();

        builder.Services.AddTransient<ISessionManager, SessionManagerManager>();

        builder.Services
            .AddAuthentication(CustomJwtAuthentication.Scheme)
            .AddScheme<CustomJwtAuthenticationOptions, CustomJwtAuthenticationHandler>(CustomJwtAuthentication.Scheme,
                null);

        builder.Services
            .AddAuthorization(options =>
            {
                options.InvokeHandlersAfterFailure = false;
                options.DefaultPolicy = new AuthorizationPolicyBuilder()
                    .RequireAuthenticatedUser()
                    .Build();
            });
    }
}