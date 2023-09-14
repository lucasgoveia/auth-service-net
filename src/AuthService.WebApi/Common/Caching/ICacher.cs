namespace AuthService.WebApi.Common.Caching;

public interface ICacher
{
    Task<T?> Get<T>(string key);
    Task<T> GetOrSet<T>(string key, Func<Task<T>> fetchData, TimeSpan? expiry = null);
    Task Set<T>(string key, T data, TimeSpan? expiry = null);
    Task Remove(string key);
    Task<T?> GetAndRemove<T>(string key);
}