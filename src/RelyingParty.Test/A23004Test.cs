using System.IdentityModel.Tokens.Jwt;
using System.Security.Cryptography;
using System.Text.Json;
using Com.Bayoomed.TelematikFederation;
using Com.Bayoomed.TelematikFederation.Controllers.OidcFederation;
using Com.Bayoomed.TelematikFederation.OidcResponse;
using Com.Bayoomed.TelematikFederation.Services;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Moq;

namespace RelyingParty.Test;

[TestClass]
public class A23004Test
{
    /// <summary>
    ///     A_23004 - Anforderung eines Vertrauensniveaus
    ///     Fachdienste MÜSSEN eine Authentisierung auf dem für den Zugriff auf ihre Fachdaten notwendigen Vertrauensniveau im
    ///     Parameter acr_values des Pushed Authorization-Request anfragen oder, wenn nur ein Wert infrage kommt diesen im Feld
    ///     default_acr_values ihres Entity Statements nennen
    /// </summary>
    [TestMethod]
    public void A23004_EntityStatementContainsAcr()
    {
        var opt = new Mock<IOptions<OidcFedOptions>>();
        opt.Setup(o => o.Value).Returns(new OidcFedOptions
        {
            FedMasterJwks = new JsonWebKeySet(),
            FederationMaster = "https://federationmaster",
            Issuer = "issuer",
            ClientName = "clientname",
            SignPrivKey = ECDsa.Create().ExportECPrivateKeyPem()
        });
        var cnt = new EntityStatementController(opt.Object);
        var res = cnt.Get();
        var token = new JwtSecurityTokenHandler().ReadToken(res.Content) as JwtSecurityToken;
        var acr = (token.Payload["metadata"] as JsonElement? ?? default)
            .GetProperty("openid_relying_party").GetProperty("default_acr_values").GetString();
        Assert.AreEqual("gematik-ehealth-loa-high", acr);
    }

    /// <summary>
    ///     A_23004 - Anforderung eines Vertrauensniveaus
    ///     Fachdienste MÜSSEN eine Authentisierung auf dem für den Zugriff auf ihre Fachdaten notwendigen Vertrauensniveau im
    ///     Parameter acr_values des Pushed Authorization-Request anfragen oder, wenn nur ein Wert infrage kommt diesen im Feld
    ///     default_acr_values ihres Entity Statements nennen
    /// </summary>
    [TestMethod]
    public async Task A23004_ParContainsAcr()
    {
        var secEs = new Mock<ISectorIdPEntityStatementService>();


        secEs.Setup(s => s.GetSectorIdPEntityStatement(It.IsAny<string>(), It.IsAny<bool>()))
            .ReturnsAsync(JwtPayload.Deserialize("""
                                                 {
                                                 "metadata": {
                                                    "openid_provider": {
                                                            "pushed_authorization_request_endpoint": "https://par",
                                                            "authorization_endpoint": "https//secauth/auth"
                                                        }
                                                    }
                                                 }
                                                 """));
        var options = new Mock<IOptions<OidcFedOptions>>();
        options.Setup(o => o.Value).Returns(new OidcFedOptions
        {
            Issuer = "https://issuer"
        });
        var handlerMock =
            new HttpMessageHandlerMock(new StringContent(JsonSerializer.Serialize(new AuthorizationResponse())));
        var secTlsClient = new SectorIdPmTlsService(secEs.Object, options.Object, new HttpClient(handlerMock));
        _ = await secTlsClient.SendPushedAuthorizationRequest("https://sectoridp", "state");
        var req = handlerMock.Request.Content as FormUrlEncodedContent;
        var content = await req.ReadAsStringAsync();
        Assert.IsTrue(content.Contains("acr_values=gematik-ehealth-loa-high"));
    }

    public class HttpMessageHandlerMock(HttpContent returnValue) : HttpMessageHandler
    {
        public HttpRequestMessage? Request { get; private set; }

        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage? request,
            CancellationToken cancellationToken)
        {
            Request = request;
            return Task.FromResult(new HttpResponseMessage
            {
                Content = returnValue
            });
        }
    }
}