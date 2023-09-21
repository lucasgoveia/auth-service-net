using System.Text.Json;
using StackExchange.Redis;

namespace AuthService.WebApi.Common.Caching;

public class RedisCacher : ICacher
{
    private readonly IDatabase _redisDb;
    private readonly IConnectionMultiplexer _redis;
    
    public RedisCacher(IConnectionMultiplexer redisConnMultiplexer)
    {
        _redis = redisConnMultiplexer;
        _redisDb = redisConnMultiplexer.GetDatabase();
    }
    
    public async Task<T?> Get<T>(string key)
    {
        var cacheResult = await _redisDb.StringGetAsync(key);
            
        return !cacheResult.IsNullOrEmpty 
            ? JsonSerializer.Deserialize<T>(cacheResult.ToString()) 
            : default;
    }

    public async Task<(T?, TimeSpan?)> GetWithExpiration<T>(string key)
    {
        var cacheResult = await _redisDb.StringGetAsync(key);

        if (!cacheResult.IsNullOrEmpty)
            return default;
            
        var ttl = await _redisDb.KeyTimeToLiveAsync(key);
        
        return (JsonSerializer.Deserialize<T>(cacheResult.ToString()), ttl);
    }

    public async Task<T> GetOrSet<T>(string key, Func<Task<T>> fetchData, TimeSpan? expiry = null)
    {
        var cacheResult = await _redisDb.StringGetAsync(key);

        if (!cacheResult.IsNullOrEmpty) 
            return JsonSerializer.Deserialize<T>(cacheResult.ToString())!;
            
        var data = await fetchData();
        await _redisDb.StringSetAsync(key, JsonSerializer.Serialize(data), expiry);
        return data;
    }

    public async Task Set<T>(string key, T data, TimeSpan? expiry = null)
    {
        await _redisDb.StringSetAsync(key, JsonSerializer.Serialize(data), expiry);
    }

    public async Task Remove(string key)
    {
        await _redisDb.KeyDeleteAsync(new RedisKey(key));
    }

    public async Task<T?> GetAndRemove<T>(string key)
    {
        var cacheResult = await Get<T>(key);
        await Remove(key);
        return cacheResult;
    }

    public async Task ClearPattern(string pattern)
    {
        foreach (var endpoint in _redis.GetEndPoints())
        {
            var server = _redis.GetServer(endpoint);
            var keysToDelete = server.KeysAsync(pattern: pattern);
            await foreach (var key in keysToDelete)
            {
                await _redisDb.KeyDeleteAsync(key);
            }
        }
    }
}