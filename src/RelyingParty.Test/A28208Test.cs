using System.IdentityModel.Tokens.Jwt;
using System.Security.Cryptography;
using System.Text.Json;
using Com.Bayoomed.TelematikFederation;
using Com.Bayoomed.TelematikFederation.Controllers.OidcAuthServer;
using Com.Bayoomed.TelematikFederation.Controllers.OidcFederation;
using Com.Bayoomed.TelematikFederation.Services;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Moq;

namespace RelyingParty.Test;

[TestClass]
public class A28208Test
{
    /// <summary>
    ///     A_28208 - UUID v7 Generation: Generated UUID must have version 7 and variant 10.
    /// </summary>
    [TestMethod]
    public void A28208_Uuid7Generate_HasCorrectVersionAndVariant()
    {
        var uuid = Guid.CreateVersion7();
        var str = uuid.ToString();
        Assert.AreEqual(7, uuid.Version);
        // Variant: 19th char (after third hyphen) should be 8, 9, a, or b
        Assert.IsTrue("89ab".Contains(str[19]));
    }

    /// <summary>
    ///     A_28208 - UUID v7 Validation: Valid UUIDs pass, invalid ones fail.
    /// </summary>
    [TestMethod]
    public void A28208_Uuid7IsValid_DetectsVersion()
    {
        var uuid7 = Guid.CreateVersion7();
        Assert.AreEqual(7, uuid7.Version);

        // A UUID v4 should not be valid UUID v7
        var uuid4 = Guid.NewGuid();
        Assert.AreNotEqual(7, uuid4.Version);
    }

    /// <summary>
    ///     A_28208 - Entity Statement JWKS keys must have UUID v7 kid.
    /// </summary>
    [TestMethod]
    public void A28208_EntityStatement_KeyIdIsUuid7()
    {
        var keyId = Guid.CreateVersion7().ToString();
        var options = new Mock<IOptions<OidcFedOptions>>();
        options.Setup(o => o.Value).Returns(new OidcFedOptions
        {
            SignPrivKey = ECDsa.Create().ExportECPrivateKeyPem(),
            SignPrivKeyId = keyId,
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

        // kid in JWT header must be the configured UUID v7
        Assert.AreEqual(keyId, token.Header.Kid);

        // jwks in payload must contain a key with the same UUID v7 kid
        var jwksJson = ((JsonElement)token.Payload["jwks"]).GetProperty("keys").EnumerateArray();
        var sigKey = jwksJson.First(k => k.GetProperty("use").GetString() == "sig");
        Assert.AreEqual(keyId, sigKey.GetProperty("kid").GetString());
        Assert.AreEqual(7, Guid.Parse(sigKey.GetProperty("kid").GetString()!).Version);
    }

    /// <summary>
    ///     A_28208 - Signed JWKS endpoint keys must have UUID v7 kid.
    /// </summary>
    [TestMethod]
    public void A28208_SignedJwks_KeyIdIsUuid7()
    {
        var signKeyId = Guid.CreateVersion7().ToString();
        var encKeyId = Guid.CreateVersion7().ToString();
        var options = new Mock<IOptions<OidcFedOptions>>();
        options.Setup(o => o.Value).Returns(new OidcFedOptions
        {
            SignPrivKey = ECDsa.Create().ExportECPrivateKeyPem(),
            SignPrivKeyId = signKeyId,
            EncPrivKey = ECDsa.Create().ExportECPrivateKeyPem(),
            EncPrivKeyId = encKeyId,
            Issuer = "https://issuer"
        });
        var certService = new TlsClientCertificateService(
            new MemoryDistributedCache(
                new OptionsWrapper<MemoryDistributedCacheOptions>(new MemoryDistributedCacheOptions())));
        var controller = new JwksController(options.Object, certService);
        var result = controller.Get();
        var token = new JwtSecurityTokenHandler().ReadJwtToken(result.Content);

        // Header kid must be UUID v7
        Assert.AreEqual(signKeyId, token.Header.Kid);

        var keys = ((JsonElement)token.Payload["keys"]).EnumerateArray().ToList();
        var sigKeys = keys.Where(k => k.GetProperty("use").GetString() == "sig").ToList();
        var encKeys = keys.Where(k => k.GetProperty("use").GetString() == "enc").ToList();

        // At least one sig key (the EC key, not the TLS cert) should have UUID v7 kid
        Assert.IsTrue(sigKeys.Any(k => k.GetProperty("kid").GetString() == signKeyId));
        // Encryption key should have UUID v7 kid
        Assert.IsTrue(encKeys.Any(k => k.GetProperty("kid").GetString() == encKeyId));
    }

    /// <summary>
    ///     A_28208 - Auth Server JWKS key must have UUID v7 kid.
    /// </summary>
    [TestMethod]
    public void A28208_AuthServerJwks_KeyIdIsUuid7()
    {
        var keyId = Guid.CreateVersion7().ToString();
        var authOptions = new Mock<IOptions<AuthServerOptions>>();
        authOptions.Setup(o => o.Value).Returns(new AuthServerOptions
        {
            SignPrivKey = ECDsa.Create().ExportECPrivateKeyPem(),
            SignPrivKeyId = keyId,
            Issuer = "https://authserver"
        });
        var controller = new JwksAuthController(authOptions.Object);
        var result = controller.Get();
        var keySet = JsonSerializer.Deserialize<JsonWebKeySet>(
            JsonSerializer.Serialize(result.Value));
        Assert.IsNotNull(keySet);
        Assert.IsTrue(keySet.Keys.All(k => k.Kid == keyId));
        Assert.AreEqual(7, Guid.Parse(keySet.Keys.First().Kid).Version);
    }
}
