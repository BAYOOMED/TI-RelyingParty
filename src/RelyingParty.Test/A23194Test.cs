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
public class A23194Test
{
    /// <summary>
    ///     A_23194 - Veröffentlichen der öffentlichen Verschlüsselungsschlüssel
    ///     Authorization-Server MÜSSEN sicherstellen, dass die für die Verschlüsselung von ID_TOKEN durch den sektoralen
    ///     IDPs verwendeten öffentlichen Schlüssel über das Entity
    ///     Statement zur Verfügung gestellt werden, indem diese im Schlüsselsatz (jwks) des Fachdienstes abgelegt werden.
    ///     (use = enc).
    /// </summary>
    [TestMethod]
    public void A23194_PublishEncryptionKey()
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
        var enc = jwksKeys.First(k => k.Use == "enc");
        Assert.IsNotNull(enc);
    }
}