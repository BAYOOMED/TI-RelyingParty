using System.IdentityModel.Tokens.Jwt;
using Com.Bayoomed.TelematikFederation.Services;
using Microsoft.Extensions.Caching.Distributed;
using Moq;

namespace RelyingParty.Test;

[TestClass]
public class A23079Test
{
    /// <summary>
    ///     A_23079 - Gültigkeitszeitraum von Zugriffstoken
    ///     Vom Authorization-Server bereitgestellte Zugriffstoken DÜRFEN NICHT länger als 10 Minuten gültig sein.
    /// </summary>
    [TestMethod]
    public async Task A23079_AccessTokenCacheLifetimeIs10MinutesMax()
    {
        var distCache = new Mock<IDistributedCache>();
        var cache = new CacheService(distCache.Object);
        await cache.AddIdToken("any", new JwtPayload());
        distCache.Verify(d => d.SetAsync(It.IsAny<string>(), It.IsAny<byte[]>(),
            It.Is<DistributedCacheEntryOptions>(o => o.AbsoluteExpiration < DateTime.UtcNow.AddMinutes(10)),
            It.IsAny<CancellationToken>()));
    }
}