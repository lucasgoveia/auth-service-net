using AuthService.WebApi.Common;
using AuthService.WebApi.Common.Security;
using AuthService.WebApi.Common.Timestamp;
using IdGen;
using IdGen.DependencyInjection;

namespace AuthService.WebApi.Configurations;

public static class CommonServicesConfiguration
{
    public static void AddCommonServices(this WebApplicationBuilder builder)
    {
        builder.Services.AddSingleton<IPasswordHasher, PasswordHasher>();

        // IdGen
        builder.Services.AddIdGen(1,
            () => new IdGeneratorOptions(new IdStructure(41, 8, 14),
                new DefaultTimeSource(new DateTimeOffset(2023, 08, 01, 0, 0, 0, TimeSpan.Zero)))
        );
        builder.Services.AddSingleton<GenerateId>(sp =>
            () => Task.FromResult(sp.GetRequiredService<IdGenerator>().CreateId()));

        builder.Services.AddSingleton<UtcNow>(_ => TimestampUtils.UtcNow);
    }
}