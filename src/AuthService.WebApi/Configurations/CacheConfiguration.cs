using AuthService.WebApi.Common.Caching;
using StackExchange.Redis;

namespace AuthService.WebApi.Configurations;

public static class CacheConfiguration
{
    public static void AddCaching(this WebApplicationBuilder builder)
    {
        builder.Services.AddSingleton<IConnectionMultiplexer>(_ =>
            ConnectionMultiplexer.Connect(builder.Configuration.GetConnectionString("RedisConnection")!));
        builder.Services.AddSingleton<ICacher, RedisCacher>();
    }
}