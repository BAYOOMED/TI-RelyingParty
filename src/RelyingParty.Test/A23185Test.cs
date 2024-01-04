using System.IdentityModel.Tokens.Jwt;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
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
public class A23185Test
{
    
    /// <summary>
    ///     A_23185 - Gültigkeitsdauer der TLS Authentisierungsschlüssel
    ///     Authorization-Server MÜSSEN sicherstellen, dass die für die Authentisierung des Fachdienstes, als Client der mTLS
    ///     Verbindung zum sektoralen IDP, verwendeten Zertifikate eine maximale Gültigkeit von 398 Tagen haben und das
    ///     Schlüsselmaterial anschließend nicht weiterverwendet wird.
    /// </summary>
    [TestMethod]
    public void A23185_CertificateLifetime()
    {
        var options = new Mock<IOptions<OidcFedOptions>>();
        options.Setup(o => o.Value).Returns(new OidcFedOptions
        {
            EncPrivKey = ECDsa.Create().ExportECPrivateKeyPem(),
            SignPrivKey = ECDsa.Create().ExportECPrivateKeyPem(),
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
        var x5c = jwksKeys.First(k => k.Use == "sig" && k.X5c.Count > 0).X5c.First();
        var cert = new X509Certificate2(Convert.FromBase64String(x5c));
        Assert.IsTrue(cert.NotAfter - cert.NotBefore < TimeSpan.FromDays(398));
    }

    /// <summary>
    ///     A_23185 - Gültigkeitsdauer der TLS Authentisierungsschlüssel
    ///     Authorization-Server MÜSSEN sicherstellen, dass die für die Authentisierung des Fachdienstes, als Client der mTLS
    ///     Verbindung zum sektoralen IDP, verwendeten Zertifikate eine maximale Gültigkeit von 398 Tagen haben und das
    ///     Schlüsselmaterial anschließend nicht weiterverwendet wird.
    /// </summary>
    [TestMethod]
    public void A23185_KeysDiffer()
    {
        var options = new Mock<IOptions<OidcFedOptions>>();
        options.Setup(o => o.Value).Returns(new OidcFedOptions
        {
            EncPrivKey = ECDsa.Create().ExportECPrivateKeyPem(),
            SignPrivKey = ECDsa.Create().ExportECPrivateKeyPem(),
            Issuer = "https://issuer"
        });
        var memCache =
            new MemoryDistributedCache(
                new OptionsWrapper<MemoryDistributedCacheOptions>(new MemoryDistributedCacheOptions()));
        var certService = new TlsClientCertificateService(memCache);
        var cert1 = certService.GetClientCertificate().GetECDsaPublicKey();
        //we cannot wait for the cache to expire, so we remove the cert from the cache
        memCache.Remove("clientCertPem");
        var cert2 = certService.GetClientCertificate().GetECDsaPublicKey();
        Assert.IsFalse(cert1.ExportParameters(false).Q.X.SequenceEqual(cert2.ExportParameters(false).Q.X));
        Assert.IsFalse(cert1.ExportParameters(false).Q.Y.SequenceEqual(cert2.ExportParameters(false).Q.Y));
    }
}


