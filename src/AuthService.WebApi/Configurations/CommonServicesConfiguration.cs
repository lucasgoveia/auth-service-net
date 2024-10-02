using AuthService.Common.Security;
using AuthService.Common.Timestamp;
using AuthService.WebApi.Common;
using AuthService.WebApi.Common.Auth;

namespace AuthService.WebApi.Configurations;

public static class CommonServicesConfiguration
{
    public static void AddCommonServices(this WebApplicationBuilder builder)
    {
        builder.Services.AddSingleton<IPasswordHasher, PasswordHasher>();
        builder.Services.AddSingleton<ISecureKeyGenerator, SecureKeyGenerator>();
        builder.Services.AddSingleton<IAesEncryptor, AesEncryptor>();
        builder.Services.AddSingleton<IOtpGenerator, OtpGenerator>();

        builder.Services.AddScoped<ISessionRepository, SessionRepository>();

        builder.Services.AddSingleton<UtcNow>(_ => TimestampUtils.UtcNow);

        builder.Services.AddScoped<RequestPipe>();
    }
}