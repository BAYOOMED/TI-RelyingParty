using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Web;
using Com.Bayoomed.TelematikFederation;
using Com.Bayoomed.TelematikFederation.Controllers.OidcFederation;
using Com.Bayoomed.TelematikFederation.OidcRequest;
using Com.Bayoomed.TelematikFederation.Services;
using Jose;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Moq;

namespace RelyingParty.Test;

[TestClass]
public class A27505Test
{
    private Mock<IOptions<AuthServerOptions>> authOptions = null!;
    private Mock<ICacheService> cache = null!;
    private ECDsa encPrivKey = null!;
    private Mock<IOptions<OidcFedOptions>> options = null!;
    private Mock<ISectorIdPEntityStatementService> secIdpEsService = null!;

    /// <summary>
    ///     A_27505 - Signalisierung TI-Feature-Versionen im Entity Statement
    ///     Prüft, dass version=1.0.0 im JWE Protected Header korrekt erkannt wird.
    /// </summary>
    [TestMethod]
    public async Task A27505_VersionExplicit1_0_0()
    {
        Setup();
        var (_, _, _, _, cnt) = SetupCallbackTest("1.0.0");

        var cb = await cnt.Callback("code", "state", null, null);

        Assert.IsInstanceOfType(cb, typeof(RedirectResult));
        var para = HttpUtility.ParseQueryString(new Uri(((RedirectResult)cb).Url).Query);
        Assert.AreEqual("thisisthecode", para["code"]);
        Assert.IsNull(para["error"]);
    }

    /// <summary>
    ///     A_27505 - Signalisierung TI-Feature-Versionen im Entity Statement
    ///     Hinweis 1: Das Fehlen des version-Tags im JWE Protected Header ist als version=1.0.0 zu interpretieren.
    /// </summary>
    [TestMethod]
    public async Task A27505_VersionMissingDefaultsTo1_0_0()
    {
        Setup();
        var (_, _, _, _, cnt) = SetupCallbackTest(null);

        var cb = await cnt.Callback("code", "state", null, null);

        Assert.IsInstanceOfType(cb, typeof(RedirectResult));
        var para = HttpUtility.ParseQueryString(new Uri(((RedirectResult)cb).Url).Query);
        Assert.AreEqual("thisisthecode", para["code"]);
        Assert.IsNull(para["error"]);
    }

    /// <summary>
    ///     A_27505 - Signalisierung TI-Feature-Versionen im Entity Statement
    ///     Prüft, dass version=2.0.0 im JWE Protected Header korrekt erkannt wird.
    /// </summary>
    [TestMethod]
    public async Task A27505_Version2_0_0()
    {
        Setup(withTiFeatures: true);
        var (_, _, _, _, cnt) = SetupCallbackTest("2.0.0");

        var cb = await cnt.Callback("code", "state", null, null);

        Assert.IsInstanceOfType(cb, typeof(RedirectResult));
        var para = HttpUtility.ParseQueryString(new Uri(((RedirectResult)cb).Url).Query);
        Assert.AreEqual("thisisthecode", para["code"]);
        Assert.IsNull(para["error"]);
    }

    /// <summary>
    ///     A_27505 Hinweis 3 - Wenn version=2.0.0 im JWE Header, aber Entity Statement des sek. IDP
    ///     diese Version nicht unter id_token_version_supported listet, muss das ES aktualisiert werden.
    /// </summary>
    [TestMethod]
    public async Task A27505_Version2_0_0_RefreshesEntityStatementIfNotSupported()
    {
        Setup(withTiFeatures: false);
        var (_, _, _, _, cnt) = SetupCallbackTest("2.0.0");

        var cb = await cnt.Callback("code", "state", null, null);

        Assert.IsInstanceOfType(cb, typeof(RedirectResult));
        var para = HttpUtility.ParseQueryString(new Uri(((RedirectResult)cb).Url).Query);
        Assert.AreEqual("thisisthecode", para["code"]);
        Assert.IsNull(para["error"]);
        // Verify that the entity statement was refreshed (forceRefresh=true)
        secIdpEsService.Verify(
            s => s.GetSectorIdPEntityStatement(It.IsAny<string>(), true), Times.Once);
    }


    private (ECDsa signKey, JsonWebKey signJwk, Mock<ISectorIdPmTlsService> secIdPmTlsService,
        Mock<ILogger<FedCallbackController>> logger, FedCallbackController cnt) SetupCallbackTest(string? version)
    {
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
        var encodedToken = EncryptToken(encPrivKey, rawToken, version);
        secIdPmTlsService.Setup(s => s.SendTokenRequest(It.IsAny<TokenRequest>(), It.IsAny<string>()))
            .ReturnsAsync(encodedToken);
        var logger = new Mock<ILogger<FedCallbackController>>();
        var cnt = new FedCallbackController(cache.Object, options.Object, authOptions.Object, secIdpEsService.Object,
            secIdPmTlsService.Object, logger.Object);
        return (signKey, signJwk, secIdPmTlsService, logger, cnt);
    }

    private void Setup(bool withTiFeatures = false)
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
        cache.Setup(c => c.AddAuthorizationRequest(It.IsAny<AuthorizationRequest>(), It.IsAny<string>()))
            .ReturnsAsync("thisisthecode");
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

        var esJson = withTiFeatures
            ? """
              {
                  "metadata": {
                      "openid_provider": {
                          "token_endpoint": "https://secidp/token",
                          "ti_features_supported": {
                              "id_token_version_supported": ["1.0.0", "2.0.0"]
                          }
                      }
                  }
              }
              """
            : """
              {
                  "metadata": {
                      "openid_provider": {
                          "token_endpoint": "https://secidp/token"
                      }
                  }
              }
              """;

        secIdpEsService.Setup(s => s.GetSectorIdPEntityStatement(It.IsAny<string>(), It.IsAny<bool>()))
            .ReturnsAsync(JwtPayload.Deserialize(esJson));
    }

    private static string EncryptToken(ECDsa encPrivKey, string rawToken, string? version)
    {
        var jwk = JsonWebKeyConverter.ConvertFromECDsaSecurityKey(new ECDsaSecurityKey(encPrivKey));
        jwk.KeyId = Base64UrlEncoder.Encode(jwk.ComputeJwkThumbprint());
        var joseJwk = new Jwk("P-256", jwk.X, jwk.Y, null);
        joseJwk.KeyId = jwk.KeyId;
        var extraHeaders = new Dictionary<string, object> { { "kid", jwk.KeyId }, { "cty", "JWT" } };
        if (version != null)
            extraHeaders["version"] = version;
        var encodedToken = JWT.Encode(rawToken, joseJwk, JweAlgorithm.ECDH_ES, JweEncryption.A256GCM, null,
            extraHeaders);
        return encodedToken;
    }
}
