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

/// <summary>
/// A_23202-02: Akzeptanz loa-substantial bei amr mEW oder sso (befristet)
/// A_27593: Akzeptanz loa-substantial via Consent-Claim
/// </summary>
[TestClass]
public class A23202Test
{
    private Mock<IOptions<AuthServerOptions>> _authOptions = null!;
    private Mock<ICacheService> _cache = null!;
    private ECDsa _encPrivKey = null!;
    private Mock<IOptions<OidcFedOptions>> _options = null!;
    private Mock<ISectorIdPEntityStatementService> _secIdpEsService = null!;

    /// <summary>
    /// A_23202-02: loa-substantial with amr=urn:telematik:auth:mEW must be accepted.
    /// </summary>
    [TestMethod]
    public async Task A23202_SubstantialWithAmrMew_Accepted()
    {
        var cb = await CallbackWithClaims(
            new Claim("acr", "gematik-ehealth-loa-substantial"),
            new Claim("amr", "urn:telematik:auth:mEW"));

        AssertSuccess(cb);
    }

    /// <summary>
    /// A_23202-02: loa-substantial with amr=urn:telematik:auth:sso must be accepted.
    /// </summary>
    [TestMethod]
    public async Task A23202_SubstantialWithAmrSso_Accepted()
    {
        var cb = await CallbackWithClaims(
            new Claim("acr", "gematik-ehealth-loa-substantial"),
            new Claim("amr", "urn:telematik:auth:sso"));

        AssertSuccess(cb);
    }

    /// <summary>
    /// A_27593: loa-substantial with urn:telematik:auth:consent=loa-substantial must be accepted.
    /// </summary>
    [TestMethod]
    public async Task A27593_SubstantialWithConsentClaim_Accepted()
    {
        var cb = await CallbackWithClaims(
            new Claim("acr", "gematik-ehealth-loa-substantial"),
            new Claim("urn:telematik:auth:consent", "loa-substantial"));

        AssertSuccess(cb);
    }

    /// <summary>
    /// A_27593: loa-substantial with consent + interactive claim must be accepted.
    /// </summary>
    [TestMethod]
    public async Task A27593_SubstantialWithConsentAndInteractive_Accepted()
    {
        var cb = await CallbackWithClaims(
            new Claim("acr", "gematik-ehealth-loa-substantial"),
            new Claim("urn:telematik:auth:consent", "loa-substantial"),
            new Claim("urn:telematik:auth:interactive", "true"));

        AssertSuccess(cb);
    }

    /// <summary>
    /// loa-substantial without any consent mechanism must be rejected.
    /// </summary>
    [TestMethod]
    public async Task SubstantialWithoutConsent_Rejected()
    {
        var cb = await CallbackWithClaims(
            new Claim("acr", "gematik-ehealth-loa-substantial"));

        AssertError(cb);
    }

    /// <summary>
    /// loa-substantial with wrong amr value must be rejected.
    /// </summary>
    [TestMethod]
    public async Task SubstantialWithWrongAmr_Rejected()
    {
        var cb = await CallbackWithClaims(
            new Claim("acr", "gematik-ehealth-loa-substantial"),
            new Claim("amr", "urn:telematik:auth:other"));

        AssertError(cb);
    }

    /// <summary>
    /// loa-substantial with wrong consent value must be rejected.
    /// </summary>
    [TestMethod]
    public async Task SubstantialWithWrongConsentValue_Rejected()
    {
        var cb = await CallbackWithClaims(
            new Claim("acr", "gematik-ehealth-loa-substantial"),
            new Claim("urn:telematik:auth:consent", "something-else"));

        AssertError(cb);
    }

    /// <summary>
    /// loa-high is still always accepted.
    /// </summary>
    [TestMethod]
    public async Task LoaHigh_StillAccepted()
    {
        var cb = await CallbackWithClaims(
            new Claim("acr", "gematik-ehealth-loa-high"));

        AssertSuccess(cb);
    }

    private static void AssertSuccess(IActionResult cb)
    {
        Assert.IsInstanceOfType(cb, typeof(RedirectResult));
        var para = HttpUtility.ParseQueryString(new Uri(((RedirectResult)cb).Url).Query);
        Assert.AreEqual("thisisthecode", para["code"]);
        Assert.IsNull(para["error"]);
    }

    private static void AssertError(IActionResult cb)
    {
        Assert.IsInstanceOfType(cb, typeof(RedirectResult));
        var para = HttpUtility.ParseQueryString(new Uri(((RedirectResult)cb).Url).Query);
        Assert.IsNull(para["code"]);
        Assert.IsNotNull(para["error"]);
    }

    private async Task<IActionResult> CallbackWithClaims(params Claim[] extraClaims)
    {
        Setup();
        var signKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var signJwk = JsonWebKeyConverter.ConvertFromECDsaSecurityKey(new ECDsaSecurityKey(signKey));
        signJwk.Kid = Base64UrlEncoder.Encode(signJwk.ComputeJwkThumbprint());
        _secIdpEsService.Setup(s => s.GetSectorIdPJwks(It.IsAny<string>(), It.IsAny<bool>()))
            .ReturnsAsync(new JsonWebKeySet { Keys = { signJwk } });

        var secIdPmTlsService = new Mock<ISectorIdPmTlsService>();
        var claims = new List<Claim>
        {
            new("nonce", "nonce"),
            new("urn:telematik:claims:id", "1234567890")
        };
        claims.AddRange(extraClaims);

        var secToken = new JwtSecurityToken("https://secidp", "https://fedissuer",
            claims, DateTime.UtcNow, DateTime.UtcNow.AddMinutes(15),
            new SigningCredentials(new ECDsaSecurityKey(signKey), SecurityAlgorithms.EcdsaSha256));
        var rawToken = new JwtSecurityTokenHandler().WriteToken(secToken);
        var encodedToken = EncryptToken(_encPrivKey, rawToken);
        secIdPmTlsService.Setup(s => s.SendTokenRequest(It.IsAny<TokenRequest>(), It.IsAny<string>()))
            .ReturnsAsync(encodedToken);

        var logger = new Mock<ILogger<FedCallbackController>>();
        var cnt = new FedCallbackController(_cache.Object, _options.Object, _authOptions.Object,
            _secIdpEsService.Object, secIdPmTlsService.Object, logger.Object);

        return await cnt.Callback("code", "state", null, null);
    }

    private void Setup()
    {
        _cache = new Mock<ICacheService>();
        _cache.Setup(c => c.GetAndRemoveAuthorizationRequest(It.IsAny<string>())).ReturnsAsync(
            new AuthorizationRequest
            {
                client_id = "client",
                redirect_uri = "https://client/cb",
                nonce = "nonce"
            });
        _cache.Setup(c => c.GetAndRemoveParResponse(It.IsAny<string>())).ReturnsAsync(
            new ParResponse(new AuthorizationRequest { nonce = "nonce" }, "verifier", "https://secauth",
                "https://secidp"));
        _cache.Setup(c => c.AddAuthorizationRequest(It.IsAny<AuthorizationRequest>(), It.IsAny<string>()))
            .ReturnsAsync("thisisthecode");
        _options = new Mock<IOptions<OidcFedOptions>>();
        _encPrivKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        _options.Setup(o => o.Value).Returns(new OidcFedOptions
        {
            Issuer = "https://fedissuer",
            EncPrivKey = _encPrivKey.ExportECPrivateKeyPem()
        });
        _authOptions = new Mock<IOptions<AuthServerOptions>>();
        _authOptions.Setup(o => o.Value).Returns(new AuthServerOptions
        {
            Issuer = "https://authissuer"
        });
        _secIdpEsService = new Mock<ISectorIdPEntityStatementService>();
        _secIdpEsService.Setup(s => s.GetSectorIdPEntityStatement(It.IsAny<string>(), It.IsAny<bool>()))
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
        return JWT.Encode(rawToken, joseJwk, JweAlgorithm.ECDH_ES, JweEncryption.A256GCM, null,
            new Dictionary<string, object> { { "kid", jwk.KeyId }, { "cty", "JWT" } });
    }
}
