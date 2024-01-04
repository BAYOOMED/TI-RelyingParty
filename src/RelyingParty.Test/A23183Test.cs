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
public class A23183Test
{
    /// <summary>
    ///     A_23183 - Veröffentlichen der TLS Authentisierungsschlüssel
    ///     Authorization-Server MÜSSEN sicherstellen, dass die für die TLS Client Authentisierung gegenüber sektoralen IDPs
    ///     verwendeten Schlüssel über das Entity Statement validiert werden können, indem für diese Zertifikate im
    ///     Schlüsselsatz (jwks) des Fachdienstes abgelegt werden. ("use = sig", x5c Objekt gesetzt). Nach [RFC8705-section
    ///     2.2 ( https://www.rfc-editor.org/rfc/rfc8705.html#name-self-signed-certificate-mut)] ist der Authorization-Server
    ///     erfolgreich authentifiziert, wenn das Zertifikat, das er während des Handshakes vorgelegt hat, mit einem der für
    ///     diesen bestimmten Client registrierten Zertifikate übereinstimmt.
    /// </summary>
    [TestMethod]
    public void A23183_JwksContainsCert()
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
        var x5c = jwksKeys.First(k => k.Use == "sig" && k.X5c.Count > 0);
        Assert.IsNotNull(x5c);
    }

    
}


