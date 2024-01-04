using System.IdentityModel.Tokens.Jwt;
using System.Security.Cryptography;
using Com.Bayoomed.TelematikFederation;
using Com.Bayoomed.TelematikFederation.Services;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Moq;

namespace RelyingParty.Test;

[TestClass]
public class A23046Test
{

    private static string GenerateES(ECDsa key)
    {
        var secKey = new ECDsaSecurityKey(key);
        secKey.KeyId = "keyId";
        var cred = new SigningCredentials(secKey, SecurityAlgorithms.EcdsaSha256);
        var token = new JwtSecurityToken("https://anymaster", "aud", null, DateTime.UtcNow,
            DateTime.UtcNow.AddMinutes(15), cred);
        return new JwtSecurityTokenHandler().WriteToken(token);
    }

    private JsonWebKeySet GenerateJwks(ECDsa key)
    {
        var secKey = new ECDsaSecurityKey(key);
        secKey.KeyId = "keyId";
        var jwk = JsonWebKeyConverter.ConvertFromECDsaSecurityKey(secKey);
        jwk.Use = "sig";
        var keySet = new JsonWebKeySet();
        keySet.Keys.Add(jwk);
        return keySet;
    }

    /// <summary>
    ///     A_23046 - öffentlicher Schlüssel des Federation Master
    ///     Anbieter von Fachdiensten MÜSSEN den öffentlichen Signaturschlüssel des Federation Master durch einen sicheren
    ///     Registrierungsprozess im Authorization-Server einbringen und initial zur Signaturprüfung verwenden.
    /// </summary>
    [TestMethod]
    public async Task A23046_FedMasterKeyReadFromSettingsAndUsedForSignatureCheck_positive()
    {
        var key = ECDsa.Create();
        var options = new Mock<IOptions<OidcFedOptions>>();
        options.Setup(o => o.Value).Returns(new OidcFedOptions
        {
            FederationMaster = "https://anymaster",
            FedMasterJwks = GenerateJwks(key)
        });
        var cache = new Mock<ICacheService>();
        var fedES = new FedMasterEntityStatementService(
            new HttpClient(new HttpMessageHandlerMock(new StringContent(GenerateES(key)))), options.Object,
            cache.Object);
        var fmes = await fedES.GetFedMasterEntityStatementAsync();
        Assert.IsNotNull(fmes);
    }
    
    /// <summary>
    ///     A_23046 - öffentlicher Schlüssel des Federation Master
    ///     Anbieter von Fachdiensten MÜSSEN den öffentlichen Signaturschlüssel des Federation Master durch einen sicheren
    ///     Registrierungsprozess im Authorization-Server einbringen und initial zur Signaturprüfung verwenden.
    /// </summary>
    [TestMethod]
    public async Task A23046_FedMasterKeyReadFromSettingsAndUsedForSignatureCheck_negative()
    {
        var key = ECDsa.Create();
        var anotherKey = ECDsa.Create();
        var options = new Mock<IOptions<OidcFedOptions>>();
        options.Setup(o => o.Value).Returns(new OidcFedOptions
        {
            FederationMaster = "https://anymaster",
            FedMasterJwks = GenerateJwks(key)
        });
        var cache = new Mock<ICacheService>();
        var fedES = new FedMasterEntityStatementService(
            new HttpClient(new HttpMessageHandlerMock(new StringContent(GenerateES(anotherKey)))), options.Object,
            cache.Object);
        await Assert.ThrowsExceptionAsync<SecurityTokenInvalidSignatureException>(() => fedES.GetFedMasterEntityStatementAsync());
    }

    public class HttpMessageHandlerMock(HttpContent returnValue) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            return Task.FromResult(new HttpResponseMessage
            {
                Content = returnValue
            });
        }
    }
}