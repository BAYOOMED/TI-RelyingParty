using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text.Json;
using Com.Bayoomed.TelematikFederation;
using Com.Bayoomed.TelematikFederation.Services;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Moq;

namespace RelyingParty.Test;

[TestClass]
public class A23040Test
{
    private static string GenerateES(ECDsa key)
    {
        var secKey = new ECDsaSecurityKey(key);
        secKey.KeyId = "keyId";
        var cred = new SigningCredentials(secKey, SecurityAlgorithms.EcdsaSha256);
        var token = new JwtSecurityToken("https://anysector", "aud", null, DateTime.UtcNow,
            DateTime.UtcNow.AddMinutes(15), cred);
        return new JwtSecurityTokenHandler().WriteToken(token);
    }

    private static string GenerateEsFromFedMaster(ECDsa fedMasterKey, ECDsa secIdPKey)
    {
        var secKey = new ECDsaSecurityKey(fedMasterKey);
        secKey.KeyId = "keyId";
        var cred = new SigningCredentials(secKey, SecurityAlgorithms.EcdsaSha256);
        var token = new JwtSecurityToken("https://anymaster", "aud", new Claim[]
            {
                new("jwks", JsonSerializer.Serialize(GenerateJwks(secIdPKey)), JsonClaimValueTypes.JsonArray)
            }, DateTime.UtcNow,
            DateTime.UtcNow.AddMinutes(15), cred);
        return new JwtSecurityTokenHandler().WriteToken(token);
    }

    private static JsonWebKeySet GenerateJwks(ECDsa key)
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
    ///     A_23040 - Fachdienst: Prüfung der Signatur des Entity Statements
    ///     Authorization-Server MÜSSEN die Signatur der heruntergeladenen Entity Statement prüfen und auf einen zeitlich
    ///     gültigen Signaturschlüssel zurückführen, welcher von dem ihm bekannten Federation Master oder von einem durch
    ///     den Federation Master beglaubigten sektoralen Identity Provider ausgestellt sein MUSS. Vor der weiteren Verwendung
    ///     MUSS die Prüfung der Entity Statements erfolgreich abgeschlossen sein.
    /// </summary>
    [TestMethod]
    public async Task A23040_SecEsSignatureCheck_positive()
    {
        var options = new Mock<IOptions<OidcFedOptions>>();
        options.Setup(o => o.Value).Returns(new OidcFedOptions
        {
            FederationMaster = "https://anymaster"
        });
        var cache = new Mock<ICacheService>();
        var fedMasterService = new Mock<IFedMasterEntityStatementService>();
        fedMasterService.Setup(f => f.GetFedMasterEntityStatementAsync()).ReturnsAsync(JwtPayload.Deserialize("""
            {
              "metadata": {
                "federation_entity": {
                  "federation_fetch_endpoint": "https://fetch"
                }
              }
            }
            """));

        var masterKey = ECDsa.Create();
        fedMasterService.Setup(f => f.GetFedMasterJwks()).ReturnsAsync(GenerateJwks(masterKey));
        var secIdpKey = ECDsa.Create();
        var seEsService =
            new SectorIdPEntityStatementService(
                new HttpClient(new HttpMessageHandlerMock(new[]
                {
                    new StringContent(GenerateES(secIdpKey)),
                    new StringContent(GenerateEsFromFedMaster(masterKey, secIdpKey))
                })),
                options.Object,
                cache.Object,
                fedMasterService.Object);

        var secEs = await seEsService.GetSectorIdPEntityStatement("https://anysector");

        Assert.IsNotNull(secEs);
    }

    /// <summary>
    ///     A_23040 - Fachdienst: Prüfung der Signatur des Entity Statements
    ///     Authorization-Server MÜSSEN die Signatur der heruntergeladenen Entity Statement prüfen und auf einen zeitlich
    ///     gültigen Signaturschlüssel zurückführen, welcher von dem ihm bekannten Federation Master oder von einem durch
    ///     den Federation Master beglaubigten sektoralen Identity Provider ausgestellt sein MUSS. Vor der weiteren Verwendung
    ///     MUSS die Prüfung der Entity Statements erfolgreich abgeschlossen sein.
    /// </summary>
    [TestMethod]
    public async Task A23040_SecEsSignatureCheck_negative()
    {
        var options = new Mock<IOptions<OidcFedOptions>>();
        options.Setup(o => o.Value).Returns(new OidcFedOptions
        {
            FederationMaster = "https://anymaster"
        });
        var cache = new Mock<ICacheService>();
        var fedMasterService = new Mock<IFedMasterEntityStatementService>();
        fedMasterService.Setup(f => f.GetFedMasterEntityStatementAsync()).ReturnsAsync(JwtPayload.Deserialize("""
            {
              "metadata": {
                "federation_entity": {
                  "federation_fetch_endpoint": "https://fetch"
                }
              }
            }
            """));

        var masterKey = ECDsa.Create();
        fedMasterService.Setup(f => f.GetFedMasterJwks()).ReturnsAsync(GenerateJwks(masterKey));
        var secIdpKey = ECDsa.Create();
        var wrongKey = ECDsa.Create();
        var seEsService =
            new SectorIdPEntityStatementService(
                new HttpClient(new HttpMessageHandlerMock(new[]
                {
                    new StringContent(GenerateES(secIdpKey)),
                    new StringContent(GenerateEsFromFedMaster(masterKey, wrongKey))
                })),
                options.Object,
                cache.Object,
                fedMasterService.Object);
        
        await Assert.ThrowsExceptionAsync<SecurityTokenInvalidSignatureException>(() =>
            seEsService.GetSectorIdPEntityStatement("https://anysector"));

    }

    public class HttpMessageHandlerMock(StringContent[] returnValues) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            var value = returnValues.First();
            returnValues = returnValues.Skip(1).ToArray();
            return Task.FromResult(new HttpResponseMessage
            {
                Content = value
            });
        }
    }
}