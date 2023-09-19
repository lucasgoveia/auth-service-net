using System.Text.Json;
using AuthService.WebApi.Common.Caching;

namespace AuthService.WebApi.Tests.Fakes;

public class FakeCacher : ICacher
{
    private readonly IDictionary<string, string> _cache = new Dictionary<string, string>();

    public Task<T?> Get<T>(string key)
    {
        if (_cache.TryGetValue(key, out var valueJson))
            return Task.FromResult(JsonSerializer.Deserialize<T>(valueJson!));
        
        return Task.FromResult<T?>(default);
    }

    public async Task<(T?, TimeSpan?)> GetWithExpiration<T>(string key)
    {
        return (await Get<T>(key), null);
    }

    public async Task<T> GetOrSet<T>(string key, Func<Task<T>> fetchData, TimeSpan? expiry = null)
    {
        var hasValue = _cache.TryGetValue(key, out var valueJson);

        if (!hasValue || string.IsNullOrEmpty(valueJson))
        {
            var value = await fetchData();

            if (_cache.ContainsKey(key))
                _cache[key] = JsonSerializer.Serialize(value);
            else
                _cache.Add(key, JsonSerializer.Serialize(value));

            return value;
        }

        return JsonSerializer.Deserialize<T>(valueJson!)!;
    }

    public Task Set<T>(string key, T data, TimeSpan? expiry = null)
    {
        if (_cache.ContainsKey(key))
            _cache[key] = JsonSerializer.Serialize(data);
        else
            _cache.Add(key, JsonSerializer.Serialize(data));

        return Task.CompletedTask;
    }

    public Task Remove(string key)
    {
        _cache.Remove(key);

        return Task.CompletedTask;
    }

    public Task<T?> GetAndRemove<T>(string key)
    {
        var valueJson = _cache[key];

        _cache.Remove(key);

        if (string.IsNullOrEmpty(valueJson))
            return Task.FromResult<T?>(default);

        return Task.FromResult(JsonSerializer.Deserialize<T>(valueJson));
    }

    public Task Reset()
    {
        _cache.Clear();
        return Task.CompletedTask;
    }
}