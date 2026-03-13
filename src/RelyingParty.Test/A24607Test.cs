using System.IdentityModel.Tokens.Jwt;
using System.Security.Cryptography;
using System.Text.Json;
using Com.Bayoomed.TelematikFederation;
using Com.Bayoomed.TelematikFederation.Controllers.OidcFederation;
using Com.Bayoomed.TelematikFederation.Services;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Options;
using Moq;

namespace RelyingParty.Test;

[TestClass]
public class A24607Test
{
    /// <summary>
    ///     A_24607 - When NextSignPrivKey is configured, the Entity Statement JWKS contains both
    ///     the current and next signing public keys so the next key can be deposited at the
    ///     Federation Master before use.
    /// </summary>
    [TestMethod]
    public void A24607_EntityStatement_IncludesNextSigningKey()
    {
        var currentKeyId = Guid.CreateVersion7().ToString();
        var nextKeyId = Guid.CreateVersion7().ToString();
        var options = new Mock<IOptions<OidcFedOptions>>();
        options.Setup(o => o.Value).Returns(new OidcFedOptions
        {
            SignPrivKey = ECDsa.Create().ExportECPrivateKeyPem(),
            SignPrivKeyId = currentKeyId,
            NextSignPrivKey = ECDsa.Create().ExportECPrivateKeyPem(),
            NextSignPrivKeyId = nextKeyId,
            EncPrivKey = ECDsa.Create().ExportECPrivateKeyPem(),
            EncPrivKeyId = Guid.CreateVersion7().ToString(),
            Issuer = "https://issuer",
            ClientName = "Test",
            OrganizationName = "Test Org",
            FederationMaster = "https://fedmaster",
            Scope = "openid"
        });
        var controller = new EntityStatementController(options.Object);
        var result = controller.Get();
        var token = new JwtSecurityTokenHandler().ReadJwtToken(result.Content);

        // Entity statement is signed with the CURRENT key
        Assert.AreEqual(currentKeyId, token.Header.Kid);

        // JWKS must contain both keys
        var jwksKeys = ((JsonElement)token.Payload["jwks"]).GetProperty("keys").EnumerateArray().ToList();
        var kids = jwksKeys.Select(k => k.GetProperty("kid").GetString()).ToList();
        Assert.IsTrue(kids.Contains(currentKeyId), "current signing key should be in JWKS");
        Assert.IsTrue(kids.Contains(nextKeyId), "next signing key should be in JWKS");
        Assert.AreEqual(2, jwksKeys.Count, "should have exactly 2 keys (current + next)");
    }

    /// <summary>
    ///     A_24607 - When NextSignPrivKey is NOT configured, Entity Statement JWKS contains only
    ///     the current signing key.
    /// </summary>
    [TestMethod]
    public void A24607_EntityStatement_OnlyCurrentKeyWhenNoNext()
    {
        var currentKeyId = Guid.CreateVersion7().ToString();
        var options = new Mock<IOptions<OidcFedOptions>>();
        options.Setup(o => o.Value).Returns(new OidcFedOptions
        {
            SignPrivKey = ECDsa.Create().ExportECPrivateKeyPem(),
            SignPrivKeyId = currentKeyId,
            EncPrivKey = ECDsa.Create().ExportECPrivateKeyPem(),
            EncPrivKeyId = Guid.CreateVersion7().ToString(),
            Issuer = "https://issuer",
            ClientName = "Test",
            OrganizationName = "Test Org",
            FederationMaster = "https://fedmaster",
            Scope = "openid"
        });
        var controller = new EntityStatementController(options.Object);
        var result = controller.Get();
        var token = new JwtSecurityTokenHandler().ReadJwtToken(result.Content);
        var jwksKeys = ((JsonElement)token.Payload["jwks"]).GetProperty("keys").EnumerateArray().ToList();
        Assert.AreEqual(1, jwksKeys.Count, "should have 1 key when no next key configured");
    }

    /// <summary>
    ///     A_24607 - Signed JWKS also includes the next signing key when configured.
    /// </summary>
    [TestMethod]
    public void A24607_SignedJwks_IncludesNextSigningKey()
    {
        var currentKeyId = Guid.CreateVersion7().ToString();
        var nextKeyId = Guid.CreateVersion7().ToString();
        var options = new Mock<IOptions<OidcFedOptions>>();
        options.Setup(o => o.Value).Returns(new OidcFedOptions
        {
            SignPrivKey = ECDsa.Create().ExportECPrivateKeyPem(),
            SignPrivKeyId = currentKeyId,
            NextSignPrivKey = ECDsa.Create().ExportECPrivateKeyPem(),
            NextSignPrivKeyId = nextKeyId,
            EncPrivKey = ECDsa.Create().ExportECPrivateKeyPem(),
            EncPrivKeyId = Guid.CreateVersion7().ToString(),
            Issuer = "https://issuer"
        });
        var certService = new TlsClientCertificateService(
            new MemoryDistributedCache(
                new OptionsWrapper<MemoryDistributedCacheOptions>(new MemoryDistributedCacheOptions())));
        var controller = new JwksController(options.Object, certService);
        var result = controller.Get();
        var token = new JwtSecurityTokenHandler().ReadJwtToken(result.Content);
        var keys = ((JsonElement)token.Payload["keys"]).EnumerateArray().ToList();
        var sigKeys = keys.Where(k => k.GetProperty("use").GetString() == "sig").ToList();
        var kids = sigKeys.Select(k => k.GetProperty("kid").GetString()).ToList();
        Assert.IsTrue(kids.Contains(currentKeyId), "current signing key should be in signed JWKS");
        Assert.IsTrue(kids.Contains(nextKeyId), "next signing key should be in signed JWKS");
    }
}
