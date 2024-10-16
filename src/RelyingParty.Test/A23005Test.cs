using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Web;
using Com.Bayoomed.TelematikFederation;
using Com.Bayoomed.TelematikFederation.Controllers.OidcFederation;
using Com.Bayoomed.TelematikFederation.OidcRequest;
using Com.Bayoomed.TelematikFederation.OidcResponse;
using Com.Bayoomed.TelematikFederation.Services;
using Jose;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Moq;

namespace RelyingParty.Test;

[TestClass]
public class A23005Test
{
    private Mock<IOptions<AuthServerOptions>> authOptions;
    private Mock<ICacheService> cache;
    private ECDsa encPrivKey;
    private Mock<IOptions<OidcFedOptions>> options;
    private Mock<ISectorIdPEntityStatementService> secIdpEsService;

    /// <summary>
    /// A_23005 - Verifikation des durchgeführten Vertrauensniveaus 
    /// Fachdienste MÜSSEN prüfen, ob das im ID_TOKEN im Feld acr gelistete Vertrauensniveau
    /// der durchgeführten Authentisierung für den Zugriff auf ihre Fachdaten ausreicht.
    /// </summary>
    [TestMethod]
    public async Task A23005_WorksWithAcrValueHigh()
    {
        Setup();
        var signKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var signJwk = JsonWebKeyConverter.ConvertFromECDsaSecurityKey(new ECDsaSecurityKey(signKey));
        signJwk.Kid = Base64UrlEncoder.Encode(signJwk.ComputeJwkThumbprint());
        secIdpEsService.Setup(s => s.GetSectorIdPJwks(It.IsAny<string>(), It.IsAny<bool>()))
            .ReturnsAsync(new JsonWebKeySet { Keys = { signJwk } });
        var secIdPmTlsService = new Mock<ISectorIdPmTlsService>();
        var secToken = new JwtSecurityToken("https://secidp", "https://fedissuer", new[]
            {
                new Claim("nonce", "nonce"),
                new Claim("urn:telematik:claims:id", "1234567890"),
                new Claim("acr", "gematik-ehealth-loa-high")
            }, DateTime.UtcNow, DateTime.UtcNow.AddMinutes(15),
            new SigningCredentials(new ECDsaSecurityKey(signKey), SecurityAlgorithms.EcdsaSha256));
        var rawToken = new JwtSecurityTokenHandler().WriteToken(secToken);
        var encodedToken = EncryptToken(encPrivKey, rawToken);
        secIdPmTlsService.Setup(s => s.SendTokenRequest(It.IsAny<TokenRequest>(), It.IsAny<string>()))
            .ReturnsAsync(encodedToken);
        var logger = new Mock<ILogger<FedCallbackController>>();
        var cnt = new FedCallbackController(cache.Object, options.Object, authOptions.Object, secIdpEsService.Object,
            secIdPmTlsService.Object, logger.Object);
        
        var cb = await cnt.Callback("code", "state", null, null);

        Assert.IsInstanceOfType(cb, typeof(RedirectResult));
        var para = HttpUtility.ParseQueryString(new Uri(((RedirectResult)cb).Url).Query);
        Assert.AreEqual("thisisthecode", para["code"]);
        Assert.IsNull(para["error"]);
    }

    /// <summary>
    /// A_23005 - Verifikation des durchgeführten Vertrauensniveaus 
    /// Fachdienste MÜSSEN prüfen, ob das im ID_TOKEN im Feld acr gelistete Vertrauensniveau
    /// der durchgeführten Authentisierung für den Zugriff auf ihre Fachdaten ausreicht.
    /// </summary>
    [TestMethod]
    public async Task A23005_WorksWithAcrValueSubstancial()
    {
        Setup();
        var signKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var signJwk = JsonWebKeyConverter.ConvertFromECDsaSecurityKey(new ECDsaSecurityKey(signKey));
        signJwk.Kid = Base64UrlEncoder.Encode(signJwk.ComputeJwkThumbprint());
        secIdpEsService.Setup(s => s.GetSectorIdPJwks(It.IsAny<string>(), It.IsAny<bool>()))
            .ReturnsAsync(new JsonWebKeySet { Keys = { signJwk } });
        var secIdPmTlsService = new Mock<ISectorIdPmTlsService>();

        // first try with gematik-ehealth-loa-substancial
        var secToken = new JwtSecurityToken("https://secidp", "https://fedissuer", new[]
            {
                new Claim("nonce", "nonce"),
                new Claim("urn:telematik:claims:id", "1234567890"),
                new Claim("acr", "gematik-ehealth-loa-high")
            }, DateTime.UtcNow, DateTime.UtcNow.AddMinutes(15),
            new SigningCredentials(new ECDsaSecurityKey(signKey), SecurityAlgorithms.EcdsaSha256));
        var rawToken = new JwtSecurityTokenHandler().WriteToken(secToken);
        var encodedToken = EncryptToken(encPrivKey, rawToken);
        secIdPmTlsService.Setup(s => s.SendTokenRequest(It.IsAny<TokenRequest>(), It.IsAny<string>()))
            .ReturnsAsync(encodedToken);
        var logger = new Mock<ILogger<FedCallbackController>>();
        var cnt = new FedCallbackController(cache.Object, options.Object, authOptions.Object, secIdpEsService.Object,
            secIdPmTlsService.Object, logger.Object);
        
        var cb = await cnt.Callback("code", "state", null, null);

        Assert.IsInstanceOfType(cb, typeof(RedirectResult));
        var para = HttpUtility.ParseQueryString(new Uri(((RedirectResult)cb).Url).Query);
        Assert.AreEqual("thisisthecode", para["code"]);
        Assert.IsNull(para["error"]);
    }

    /// <summary>
    /// A_23005 - Verifikation des durchgeführten Vertrauensniveaus 
    /// Fachdienste MÜSSEN prüfen, ob das im ID_TOKEN im Feld acr gelistete Vertrauensniveau
    /// der durchgeführten Authentisierung für den Zugriff auf ihre Fachdaten ausreicht.
    /// </summary>
    [TestMethod]
    public async Task A23005_FailsWithWrongAcrValue()
    {        
        Setup();
        var signKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var signJwk = JsonWebKeyConverter.ConvertFromECDsaSecurityKey(new ECDsaSecurityKey(signKey));
        signJwk.Kid = Base64UrlEncoder.Encode(signJwk.ComputeJwkThumbprint());
        secIdpEsService.Setup(s => s.GetSectorIdPJwks(It.IsAny<string>(), It.IsAny<bool>()))
            .ReturnsAsync(new JsonWebKeySet { Keys = { signJwk } });
        var secIdPmTlsService = new Mock<ISectorIdPmTlsService>();
        var secToken = new JwtSecurityToken("https://secidp", "https://fedissuer", new[]
            {
                new Claim("nonce", "nonce"),
                new Claim("urn:telematik:claims:id", "1234567890"),
                new Claim("acr", "gematik-ehealth-loa-nothighorsubstancial")
            }, DateTime.UtcNow, DateTime.UtcNow.AddMinutes(15),
            new SigningCredentials(new ECDsaSecurityKey(signKey), SecurityAlgorithms.EcdsaSha256));
        var rawToken = new JwtSecurityTokenHandler().WriteToken(secToken);
        var encodedToken = EncryptToken(encPrivKey, rawToken);
        secIdPmTlsService.Setup(s => s.SendTokenRequest(It.IsAny<TokenRequest>(), It.IsAny<string>()))
            .ReturnsAsync(encodedToken);
        var logger = new Mock<ILogger<FedCallbackController>>();
        var cnt = new FedCallbackController(cache.Object, options.Object, authOptions.Object, secIdpEsService.Object,
            secIdPmTlsService.Object, logger.Object);
        
        var cb = await cnt.Callback("code", "state", null, null);

        Assert.IsInstanceOfType(cb, typeof(RedirectResult));
        var para = HttpUtility.ParseQueryString(new Uri(((RedirectResult)cb).Url).Query);
        Assert.IsNull(para["code"]);
        Assert.IsNotNull(para["error"]);
    }

    private void Setup()
    {
        cache = new Mock<ICacheService>();
        cache.Setup(c => c.GetAndRemoveAuthorizationRequest(It.IsAny<string>())).ReturnsAsync(new AuthorizationRequest
        {
            client_id = "client",
            redirect_uri = "https://client/cb",
            nonce = "nonce"
        });
        cache.Setup(c => c.GetAndRemoveParResponse(It.IsAny<string>())).ReturnsAsync(
            new ParResponse(new AuthorizationRequest { nonce = "nonce" }, "verifier", "https://secauth",
                "https://secidp"));
        cache.Setup(c => c.AddAuthorizationRequest(It.IsAny<AuthorizationRequest>(),It.IsAny<string>())).ReturnsAsync("thisisthecode");
        options = new Mock<IOptions<OidcFedOptions>>();
        encPrivKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        options.Setup(o => o.Value).Returns(new OidcFedOptions
        {
            Issuer = "https://fedissuer",
            EncPrivKey = encPrivKey.ExportECPrivateKeyPem()
        });
        authOptions = new Mock<IOptions<AuthServerOptions>>();
        authOptions.Setup(o => o.Value).Returns(new AuthServerOptions
        {
            Issuer = "https://authissuer"
        });
        secIdpEsService = new Mock<ISectorIdPEntityStatementService>();
        secIdpEsService.Setup(s => s.GetSectorIdPEntityStatement(It.IsAny<string>(), It.IsAny<bool>()))
            .ReturnsAsync(JwtPayload.Deserialize("""
                                                 
                                                             {
                                                                 "metadata": {
                                                                     "openid_provider": {
                                                                         "token_endpoint": "https://secidp/token"
                                                                     }
                                                                 }
                                                             }
                                                             
                                                 """));
    }

    private static string EncryptToken(ECDsa encPrivKey, string rawToken)
    {
        var jwk = JsonWebKeyConverter.ConvertFromECDsaSecurityKey(new ECDsaSecurityKey(encPrivKey));
        jwk.KeyId = Base64UrlEncoder.Encode(jwk.ComputeJwkThumbprint());
        var joseJwk = new Jwk("P-256", jwk.X, jwk.Y, null);
        joseJwk.KeyId = jwk.KeyId;
        var encodedToken = JWT.Encode(rawToken, joseJwk, JweAlgorithm.ECDH_ES, JweEncryption.A256GCM, null,
            new Dictionary<string, object> { { "kid", jwk.KeyId }, { "cty", "JWT" } });
        return encodedToken;
    }
}