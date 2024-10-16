using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using Com.Bayoomed.TelematikFederation.OidcRequest;
using Com.Bayoomed.TelematikFederation.Services;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Moq;

namespace RelyingParty.Test;

[TestClass]
public class CacheServiceTest
{
    /// <summary>
    ///     Test storage and loading of JWKS object in cache
    /// </summary>
    [TestMethod]
    public async Task JwksCacheTest()
    {
        var opt = new Mock<IOptions<MemoryDistributedCacheOptions>>();
        opt.Setup(o => o.Value).Returns(new MemoryDistributedCacheOptions());
        var cache = new CacheService(new MemoryDistributedCache(opt.Object));
        var keys = new JsonWebKeySet("""
                                     {
                                         "keys": [
                                             {
                                                 "crv": "P-256",
                                                 "key_ops": [],
                                                 "kid": "puk_idp_sig",
                                                 "kty": "EC",
                                                 "oth": [],
                                                 "use": "sig",
                                                 "x": "Abt2Uyrk6KhczexlBOwJOTs_eB0DsFbcNxaxa0Z0vd4",
                                                 "x5c": [],
                                                 "y": "YZKBJtOUYEWTMknzFwBdl-6tVKyWnUDtxf2q0pST5X4"
                                             },
                                             {
                                                 "crv": "P-256",
                                                 "kid": "puk_fed_idp_token",
                                                 "kty": "EC",
                                                 "use": "sig",
                                                 "x": "YzEPFvphu4T3GgWmjPXxPT0-Pdm_Q04OLENAH98zn-M",
                                                 "y": "c8eCCyrpjAV9bZ9Igm1rAwsCH1mgo8VNmo8WBBbS3g"
                                             }
                                         ]
                                     }
                                     """);
        await cache.AddSectorIdpJwks("iss", keys, DateTime.UtcNow.AddHours(1));

        var loaded = await cache.GetSectorIdpJwks("iss");
        Assert.AreEqual(keys.Keys.Count, loaded.Keys.Count);
        Assert.IsTrue(loaded.Keys.Count(k => k.Kid == "puk_idp_sig") == 1);
        Assert.IsTrue(loaded.Keys.Count(k => k.Kid == "puk_fed_idp_token") == 1);
    }

    /// <summary>
    /// Check cache for JwtPayload (de)serialization
    /// </summary>
    [TestMethod]
    public async Task SectorIdPEntityStatementCacheTest()
    {
        var opt = new Mock<IOptions<MemoryDistributedCacheOptions>>();
        opt.Setup(o => o.Value).Returns(new MemoryDistributedCacheOptions());
        var cache = new CacheService(new MemoryDistributedCache(opt.Object));
        var payload = new JwtPayload("iss", "aud", new Claim[] { new("anything", "withvalue") }, null,
            DateTime.UtcNow.AddMinutes(10));
        await cache.AddSectorIdPEntityStatement("iss", payload);
        var loaded = await cache.GetSectorIdPEntityStatement("iss");
        Assert.AreEqual(payload.Iss, loaded.Iss);
        Assert.AreEqual("withvalue", loaded["anything"]);
        Assert.IsTrue(loaded.ValidTo > DateTime.UtcNow.AddMinutes(9));
    }

    /// <summary>
    /// GetAndRemoveAuthorizationRequest removes linked requests
    /// </summary>
    [TestMethod]
    public async Task GetAndRemoveAuthorizationRequestRemovesLinkedRequests()
    {
        var opt = new Mock<IOptions<MemoryDistributedCacheOptions>>();
        opt.Setup(o => o.Value).Returns(new MemoryDistributedCacheOptions());
        var cache = new CacheService(new MemoryDistributedCache(opt.Object));
        var code = await cache.AddAuthorizationRequest(new AuthorizationRequest());
        var code2 = await cache.AddAuthorizationRequest(new AuthorizationRequest(), code);
        var req  = await cache.GetAndRemoveAuthorizationRequest(code2);
        Assert.IsNotNull(req);
        Assert.IsNull(await cache.GetAndRemoveAuthorizationRequest(code));
        Assert.IsNull(await cache.GetAndRemoveAuthorizationRequest(code2));
    }
}