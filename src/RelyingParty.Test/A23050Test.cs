using System.IdentityModel.Tokens.Jwt;
using Com.Bayoomed.TelematikFederation.Services;
using Microsoft.Extensions.Caching.Distributed;
using Moq;

namespace RelyingParty.Test;

[TestClass]
public class A23050Test
{
    /// <summary>
    ///     A_23050 - Löschen personenbezogener Daten
    ///     Authorization-Server MÜSSEN personenbezogene Daten wie z. B. ID_TOKEN sofort nach Abschluss des
    ///     Verarbeitungsprozesses verwerfen und dürfen diese nicht dauerhaft speichern, sofern diese nicht anderweitig zu
    ///     legitimen Zwecken vorgehalten werden müssen (z. B. Protokollierung).
    /// </summary>
    [TestMethod]
    public async Task A23050_IdTokenCacheLifetimeIs10MinutesMax()
    {
        var distCache = new Mock<IDistributedCache>();
        var cache = new CacheService(distCache.Object);
        await cache.AddIdToken("any", new JwtPayload());
        distCache.Verify(d => d.SetAsync(It.IsAny<string>(), It.IsAny<byte[]>(),
            It.Is<DistributedCacheEntryOptions>(o => o.AbsoluteExpiration < DateTime.UtcNow.AddMinutes(10)),
            It.IsAny<CancellationToken>()));
    }
}