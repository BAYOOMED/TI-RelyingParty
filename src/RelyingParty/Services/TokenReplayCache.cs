using Microsoft.Extensions.Caching.Distributed;
using Microsoft.IdentityModel.Tokens;

namespace Com.Bayoomed.TelematikFederation.Services;

public class DistributedTokenReplayCache(IDistributedCache cache) : ITokenReplayCache
{
    public bool TryAdd(string securityToken, DateTime expiresOn)
    {
        cache.SetString($"replay_{securityToken}", "1", new DistributedCacheEntryOptions
        {
            AbsoluteExpiration = expiresOn
        });
        return cache.GetString(securityToken) != null;
    }

    public bool TryFind(string securityToken)
    {
        return cache.GetString($"replay_{securityToken}") != null;
    }
}