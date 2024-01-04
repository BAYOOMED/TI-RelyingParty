using System.IdentityModel.Tokens.Jwt;
using System.Security.Cryptography;
using System.Text.Json;
using Com.Bayoomed.TelematikFederation;
using Com.Bayoomed.TelematikFederation.Controllers.OidcFederation;
using Com.Bayoomed.TelematikFederation.Services;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Moq;

namespace RelyingParty.Test;

[TestClass]
public class A23196Test
{
    /// <summary>
    ///     A_23196 - Zulässige Schlüssel
    ///     Authorization-Server MÜSSEN sicherstellen, dass für TLS-Authentisierung, Token-Verschlüsselung und Signatur
    ///     seines Entity Statements nur ECC Schlüssel der Kurve P256 [RFC-5480] verwendet werden.
    /// </summary>
    [TestMethod]
    public void A23196_EcCurveIsP256()
    {
        var options = new Mock<IOptions<OidcFedOptions>>();
        options.Setup(o => o.Value).Returns(new OidcFedOptions
        {
            EncPrivKey = ECDsa.Create(ECCurve.NamedCurves.nistP256).ExportECPrivateKeyPem(),
            SignPrivKey = ECDsa.Create(ECCurve.NamedCurves.nistP256).ExportECPrivateKeyPem(),
            Issuer = "https://issuer"
        });
        var certService = new TlsClientCertificateService(
            new MemoryDistributedCache(
                new OptionsWrapper<MemoryDistributedCacheOptions>(new MemoryDistributedCacheOptions())));
        var cnt = new JwksController(options.Object, certService);
        var resp = cnt.Get();
        var token = new JwtSecurityTokenHandler().ReadJwtToken(resp.Content);
        var keys = ((JsonElement)token.Payload["keys"]).EnumerateArray();
        var jwksKeys = keys.Select(k => JsonWebKey.Create(k.ToString()));
        Assert.IsTrue(jwksKeys.All(k => k.Crv == "P-256"));
    }
}