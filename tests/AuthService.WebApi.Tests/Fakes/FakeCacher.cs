using System.Text.Json;
using AuthService.WebApi.Common.Caching;
using AuthService.WebApi.Common.Timestamp;

namespace AuthService.WebApi.Tests.Fakes;

public record FakeCacheEntry
{
    public required DateTime? Expiration { get; init; }
    public required string Value { get; init; }
}

public class FakeCacher : ICacher
{
    private readonly IDictionary<string, FakeCacheEntry> _cache = new Dictionary<string, FakeCacheEntry>();
    private readonly UtcNow _utcNow;

    public FakeCacher(UtcNow utcNow)
    {
        _utcNow = utcNow;
    }

    public Task<T?> Get<T>(string key)
    {
        if (_cache.TryGetValue(key, out var entry))
        {
            if (entry.Expiration > _utcNow())
            {
                return Task.FromResult(JsonSerializer.Deserialize<T>(entry.Value));
            }

            Remove(key);
        }

        return Task.FromResult<T?>(default);
    }

    public Task<(T?, TimeSpan?)> GetWithExpiration<T>(string key)
    {
        if (_cache.TryGetValue(key, out var entry))
        {
            if (entry.Expiration > _utcNow())
            {
                return Task.FromResult((JsonSerializer.Deserialize<T>(entry.Value), entry.Expiration - _utcNow()));
            }

            Remove(key);
        }

        return Task.FromResult<(T?, TimeSpan?)>((default, null));
    }

    public async Task<T> GetOrSet<T>(string key, Func<Task<T>> fetchData, TimeSpan? expiry = null)
    {
        if (!_cache.ContainsKey(key))
        {
            var value = await fetchData();
            _cache.Add(key,
                new FakeCacheEntry
                {
                    Expiration = _utcNow().Add(expiry ?? TimeSpan.Zero),
                    Value = JsonSerializer.Serialize(value)
                });

            return value;
        }

        return (await Get<T>(key))!;
    }

    public Task Set<T>(string key, T data, TimeSpan? expiry = null)
    {
        if (_cache.ContainsKey(key))
            _cache[key] = new FakeCacheEntry
            {
                Expiration = _utcNow().Add(expiry ?? TimeSpan.Zero),
                Value = JsonSerializer.Serialize(data)
            };
        else
            _cache.Add(key, new FakeCacheEntry
            {
                Expiration = _utcNow().Add(expiry ?? TimeSpan.Zero),
                Value = JsonSerializer.Serialize(data)
            });

        return Task.CompletedTask;
    }

    public Task Remove(string key)
    {
        _cache.Remove(key);

        return Task.CompletedTask;
    }

    public Task<T?> GetAndRemove<T>(string key)
    {
        var entry = _cache[key];

        _cache.Remove(key);

        return Task.FromResult(JsonSerializer.Deserialize<T>(entry.Value));
    }

    public Task Reset()
    {
        _cache.Clear();
        return Task.CompletedTask;
    }
}