using AuthService.Common;
using AuthService.Common.Security;
using AuthService.Common.Timestamp;
using AuthService.WebApi.Common;
using AuthService.WebApi.Common.Auth;
using IdGen;
using IdGen.DependencyInjection;

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

        // IdGen
        builder.Services.AddIdGen(1,
            () => new IdGeneratorOptions(new IdStructure(41, 8, 14),
                new DefaultTimeSource(new DateTimeOffset(2023, 08, 01, 0, 0, 0, TimeSpan.Zero)))
        );
        builder.Services.AddSingleton<GenerateId>(sp =>
            () => Task.FromResult(sp.GetRequiredService<IdGenerator>().CreateId()));

        builder.Services.AddSingleton<UtcNow>(_ => TimestampUtils.UtcNow);

        builder.Services.AddScoped<RequestPipe>();
    }
}