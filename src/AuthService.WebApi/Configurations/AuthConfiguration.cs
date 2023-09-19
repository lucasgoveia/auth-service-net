using System.Text;
using AuthService.WebApi.Common.Auth;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using ISession = AuthService.WebApi.Common.Auth.ISession;

namespace AuthService.WebApi.Configurations;

public static class AuthConfiguration
{
    public static void AddAuthSetup(this WebApplicationBuilder builder)
    {
        var jwtConfig = builder.Configuration.GetSection("JwtConfiguration");
        builder.Services.Configure<JwtConfig>(jwtConfig);
        builder.Services.AddScoped<IAuthenticationService, AuthenticationService>();
        builder.Services.AddTransient<IIdentityForLoginGetter, IdentityForLoginGetter>();
        builder.Services.AddTransient<IIdentityDeviceRepository, IdentityDeviceRepository>();
        builder.Services.AddScoped<IDeviceIdentifier, DeviceIdentifier>();

        var base64Key = jwtConfig.GetValue<string>("AccessTokenSecret");
        var issuer = jwtConfig.GetValue<string>("Issuer");

        var key = base64Key == null ? null : new SymmetricSecurityKey(Encoding.UTF8.GetBytes(base64Key));

        builder.Services.AddTransient<ISession, Session>();

        builder.Services
            .AddAuthentication(options =>
            {
                options.DefaultScheme = JwtBearerDefaults.AuthenticationScheme;
                options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
            })
            .AddJwtBearer(options =>
                // Opções de validação
                options.TokenValidationParameters = new TokenValidationParameters
                {
                    ValidateIssuerSigningKey = true,
                    IssuerSigningKey = key,
                    ValidateIssuer = true,
                    ValidateAudience = true,
                    AudienceValidator =
                        (audiences, _, _) => audiences.Any(),
                    ValidIssuer = issuer,
                    ValidateLifetime = true,
                    ClockSkew = TimeSpan.FromSeconds(30)
                }
            );
    }
}