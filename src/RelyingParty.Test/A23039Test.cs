using System.IdentityModel.Tokens.Jwt;
using Com.Bayoomed.TelematikFederation.Services;
using Microsoft.Extensions.Caching.Distributed;
using Moq;

namespace RelyingParty.Test;

[TestClass]
public class A23039Test
{
    /// <summary>
    ///     Authorization-Server KÖNNEN einmal heruntergeladene fremde Entity Statements zwischenspeichern. Diese SOLLEN nach
    ///     12 Stunden erneut heruntergeladen werden und MÜSSEN nach maximal 24 Stunden verworfen werden.
    /// </summary>
    [TestMethod]
    public async Task A23039_FedEsCacheUseExpirationIfLessThan12h()
    {
        var dCache = new Mock<IDistributedCache>();
        var cache = new CacheService(dCache.Object);
        var exp = DateTime.UtcNow.AddHours(11);
        var es = new JwtPayload("iss", "sub", null, null, exp);
        await cache.AddFedMasterEntityStatement(es);
        dCache.Verify(d => d.SetAsync(It.IsAny<string>(), It.IsAny<byte[]>(),
            It.Is<DistributedCacheEntryOptions>(o =>
                o.AbsoluteExpiration <= exp.AddMinutes(1) && o.AbsoluteExpiration >= exp.AddMinutes(-1)),
            It.IsAny<CancellationToken>()));
    }

    /// <summary>
    ///     Authorization-Server KÖNNEN einmal heruntergeladene fremde Entity Statements zwischenspeichern. Diese SOLLEN nach
    ///     12 Stunden erneut heruntergeladen werden und MÜSSEN nach maximal 24 Stunden verworfen werden.
    /// </summary>
    [TestMethod]
    public async Task A23039_FedEsCacheUse12hIfExpirationMoreThan12h()
    {
        var dCache = new Mock<IDistributedCache>();
        var cache = new CacheService(dCache.Object);
        var exp = DateTime.UtcNow.AddHours(13);
        var es = new JwtPayload("iss", "sub", null, null, exp);
        await cache.AddFedMasterEntityStatement(es);
        dCache.Verify(d => d.SetAsync(It.IsAny<string>(), It.IsAny<byte[]>(),
            It.Is<DistributedCacheEntryOptions>(o =>
                o.AbsoluteExpiration <= DateTime.UtcNow.AddHours(12).AddMinutes(1) &&
                o.AbsoluteExpiration >= DateTime.UtcNow.AddHours(12).AddMinutes(-1)),
            It.IsAny<CancellationToken>()));
    }
    
    /// <summary>
    ///     Authorization-Server KÖNNEN einmal heruntergeladene fremde Entity Statements zwischenspeichern. Diese SOLLEN nach
    ///     12 Stunden erneut heruntergeladen werden und MÜSSEN nach maximal 24 Stunden verworfen werden.
    /// </summary>
    [TestMethod]
    public async Task A23039_SecEsCacheUseExpirationIfLessThan12h()
    {
        var dCache = new Mock<IDistributedCache>();
        var cache = new CacheService(dCache.Object);
        var exp = DateTime.UtcNow.AddHours(11);
        var es = new JwtPayload("iss", "sub", null, null, exp);
        await cache.AddSectorIdPEntityStatement("iss", es);
        dCache.Verify(d => d.SetAsync(It.IsAny<string>(), It.IsAny<byte[]>(),
            It.Is<DistributedCacheEntryOptions>(o =>
                o.AbsoluteExpiration <= exp.AddMinutes(1) && o.AbsoluteExpiration >= exp.AddMinutes(-1)),
            It.IsAny<CancellationToken>()));
    }

    /// <summary>
    ///     Authorization-Server KÖNNEN einmal heruntergeladene fremde Entity Statements zwischenspeichern. Diese SOLLEN nach
    ///     12 Stunden erneut heruntergeladen werden und MÜSSEN nach maximal 24 Stunden verworfen werden.
    /// </summary>
    [TestMethod]
    public async Task A23039_SecEsCacheUse12hIfExpirationMoreThan12h()
    {
        var dCache = new Mock<IDistributedCache>();
        var cache = new CacheService(dCache.Object);
        var exp = DateTime.UtcNow.AddHours(13);
        var es = new JwtPayload("iss", "sub", null, null, exp);
        await cache.AddSectorIdPEntityStatement("iss", es);
        dCache.Verify(d => d.SetAsync(It.IsAny<string>(), It.IsAny<byte[]>(),
            It.Is<DistributedCacheEntryOptions>(o =>
                o.AbsoluteExpiration <= DateTime.UtcNow.AddHours(12).AddMinutes(1) &&
                o.AbsoluteExpiration >= DateTime.UtcNow.AddHours(12).AddMinutes(-1)),
            It.IsAny<CancellationToken>()));
    }
    
    /// <summary>
    ///     Authorization-Server KÖNNEN einmal heruntergeladene fremde Entity Statements zwischenspeichern. Diese SOLLEN nach
    ///     12 Stunden erneut heruntergeladen werden und MÜSSEN nach maximal 24 Stunden verworfen werden.
    /// </summary>
    [TestMethod]
    public async Task A23039_FedSecEsCacheUseExpirationIfLessThan12h()
    {
        var dCache = new Mock<IDistributedCache>();
        var cache = new CacheService(dCache.Object);
        var exp = DateTime.UtcNow.AddHours(11);
        var es = new JwtPayload("iss", "sub", null, null, exp);
        await cache.AddFedMasterEntityStatementForSectorIdP("iss", es);
        dCache.Verify(d => d.SetAsync(It.IsAny<string>(), It.IsAny<byte[]>(),
            It.Is<DistributedCacheEntryOptions>(o =>
                o.AbsoluteExpiration <= exp.AddMinutes(1) && o.AbsoluteExpiration >= exp.AddMinutes(-1)),
            It.IsAny<CancellationToken>()));
    }

    /// <summary>
    ///     Authorization-Server KÖNNEN einmal heruntergeladene fremde Entity Statements zwischenspeichern. Diese SOLLEN nach
    ///     12 Stunden erneut heruntergeladen werden und MÜSSEN nach maximal 24 Stunden verworfen werden.
    /// </summary>
    [TestMethod]
    public async Task A23039_FedSecEsCacheUse12hIfExpirationMoreThan12h()
    {
        var dCache = new Mock<IDistributedCache>();
        var cache = new CacheService(dCache.Object);
        var exp = DateTime.UtcNow.AddHours(13);
        var es = new JwtPayload("iss", "sub", null, null, exp);
        await cache.AddFedMasterEntityStatementForSectorIdP("iss", es);
        dCache.Verify(d => d.SetAsync(It.IsAny<string>(), It.IsAny<byte[]>(),
            It.Is<DistributedCacheEntryOptions>(o =>
                o.AbsoluteExpiration <= DateTime.UtcNow.AddHours(12).AddMinutes(1) &&
                o.AbsoluteExpiration >= DateTime.UtcNow.AddHours(12).AddMinutes(-1)),
            It.IsAny<CancellationToken>()));
    }
}