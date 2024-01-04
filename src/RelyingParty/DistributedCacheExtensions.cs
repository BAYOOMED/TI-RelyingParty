using System.IdentityModel.Tokens.Jwt;
using System.Text.Json;
using Microsoft.Extensions.Caching.Distributed;

namespace Com.Bayoomed.TelematikFederation;

/// <summary>
/// Extensions to support typed access to the IDistributedCache
/// </summary>
public static class DistributedCacheExtensions
{
    public static void Set(this IDistributedCache cache, string key, object value, TimeSpan absoluteExpiration = default)
    {
        cache.SetString(key, JsonSerializer.Serialize(value), new DistributedCacheEntryOptions()
        {
            AbsoluteExpiration = DateTimeOffset.UtcNow + absoluteExpiration
        });
    }
    public static async Task SetAsync(this IDistributedCache cache, string key, object value, TimeSpan absoluteExpiration = default)
    {
        await cache.SetStringAsync(key, JsonSerializer.Serialize(value), new DistributedCacheEntryOptions()
        {
            AbsoluteExpiration = DateTimeOffset.UtcNow + absoluteExpiration
        });
    }
    
    public static void Set(this IDistributedCache cache, string key, object value, DateTime absoluteExpiration = default)
    {
        cache.SetString(key, JsonSerializer.Serialize(value), new DistributedCacheEntryOptions()
        {
            AbsoluteExpiration = absoluteExpiration
        });
    }
    public static async Task SetAsync(this IDistributedCache cache, string key, object value, DateTime absoluteExpiration = default)
    {
        await cache.SetStringAsync(key, JsonSerializer.Serialize(value), new DistributedCacheEntryOptions()
        {
            AbsoluteExpiration = absoluteExpiration
        });
    }
    
    public static T? Get<T>(this IDistributedCache cache, string key) where T : class 
    {
        var value = cache.GetString(key);
        return value == null ? null : JsonSerializer.Deserialize<T>(value);
    }
    
    public static async Task<T?> GetAsync<T>(this IDistributedCache cache, string key) where T : class 
    {
        var value = await cache.GetStringAsync(key);
        return value == null ? null : JsonSerializer.Deserialize<T>(value);
    }
    
    public static async Task<T?> GetAndRemoveAsync<T>(this IDistributedCache cache, string key) where T : class 
    {
        var value = await cache.GetAsync<T>(key);
        await cache.RemoveAsync(key);
        return value;
    }
    
    public static async Task<JwtPayload?> GetJwtPayloadAsync(this IDistributedCache cache, string key)
    {
        var value = await cache.GetAsync<JwtPayload>(key);
        return value == null ? null : new JwtPayload(value.Claims);
    }
    
    public static async Task<JwtPayload?> GetAndRemoveJwtPayloadAsync(this IDistributedCache cache, string key)
    {
        var value = await cache.GetAndRemoveAsync<JwtPayload>(key);
        return value == null ? null : new JwtPayload(value.Claims);
    }
}