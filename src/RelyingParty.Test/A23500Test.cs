using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Text.Json;
using System.Web;
using Com.Bayoomed.TelematikFederation;
using Com.Bayoomed.TelematikFederation.OidcResponse;
using Com.Bayoomed.TelematikFederation.Services;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using Moq;

namespace RelyingParty.Test;

[TestClass]
public class A23500Test
{
    /// <summary>
    ///     A_23500 - Ablehnung des PAR als "unauthorized" (HTTP 401)
    ///     Wird der erstmalige PAR des Fachdienstes an einen sektoralen IDP mit dem Fehlercode HTTP 401 quittiert, so war der
    ///     Fachdienst dem sektoralen IDP noch nicht bekannt. Der Fachdienst MUSS in diesem Fall den PAR wiederholen.
    /// </summary>
    [TestMethod]
    public async Task A23500_RetryParOn401()
    {
        var secEs = new Mock<ISectorIdPEntityStatementService>();
        secEs.Setup(s => s.GetSectorIdPEntityStatement(It.IsAny<string>(), It.IsAny<bool>()))
            .ReturnsAsync(JwtPayload.Deserialize("""
                                                 {
                                                 "metadata": {
                                                    "openid_provider": {
                                                            "pushed_authorization_request_endpoint": "https://par",
                                                            "authorization_endpoint": "https://secauth/auth"
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
            new HttpMessageHandlerMock(new[]
            {
                new HttpResponseMessage(HttpStatusCode.Unauthorized),
                new HttpResponseMessage
                {
                    Content = new StringContent(JsonSerializer.Serialize(new AuthorizationResponse
                        { request_uri = "urn:any" }))
                }
            });
        var secTlsClient = new SectorIdPmTlsService(secEs.Object, options.Object, new HttpClient(handlerMock));
        var resp = await secTlsClient.SendPushedAuthorizationRequest("https://sectoridp", "state");
        var uri = new Uri(resp.RedirectUri);
        var query = HttpUtility.ParseQueryString(uri.Query);   
        Assert.IsTrue(uri.AbsoluteUri.StartsWith("https://secauth/auth"));
        Assert.AreEqual("urn:any",query["request_uri"]);
        Assert.AreEqual("https://issuer",query["client_id"]);
    }

    public class HttpMessageHandlerMock(HttpResponseMessage[] returnValues) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            var value = returnValues.First();
            returnValues = returnValues.Skip(1).ToArray();
            return Task.FromResult(value);
        }
    }
}