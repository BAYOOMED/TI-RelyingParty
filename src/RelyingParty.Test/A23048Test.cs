using System.IdentityModel.Tokens.Jwt;
using System.Text.Json;
using System.Web;
using Com.Bayoomed.TelematikFederation;
using Com.Bayoomed.TelematikFederation.Controllers.OidcAuthServer;
using Com.Bayoomed.TelematikFederation.OidcRequest;
using Com.Bayoomed.TelematikFederation.OidcResponse;
using Com.Bayoomed.TelematikFederation.Services;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Moq;

namespace RelyingParty.Test;

[TestClass]
public class A23048Test
{
    /// <summary>
    ///     A_23048 - Response für OAuth 2.0 Pushed Authorization Requests
    ///     Authorization-Server MÜSSEN nach Erhalt eines Authorization Request entsprechend OAuth 2.0 Pushed Authorization
    ///     Requests (PAR) https://datatracker.ietf.org/doc/html/rfc9126 mit sektoralen Identity Providern kommunizieren und
    ///     eine entsprechende Antwort an die aufrufende Instanz zurück senden.[<=]
    /// </summary>
    [TestMethod]
    public async Task A23048_RedirectForwardedToCaller()
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
            new HttpMessageHandlerMock(new StringContent(JsonSerializer.Serialize(new AuthorizationResponse
            {
                request_uri = "urn:any"
            })));
        var secTlsClient = new SectorIdPmTlsService(secEs.Object, options.Object, new HttpClient(handlerMock));
        var authOptions = new Mock<IOptions<AuthServerOptions>>();
        authOptions.Setup(o => o.Value).Returns(new AuthServerOptions
        {
            Issuer = "https://issuer/xyz",
            Clients = new List<OidcClient>
            {
                new()
                {
                    ClientId = "client",
                    RedirectUris = new List<string> { "https://redirect" }
                }
            }
        });
        var cache = new Mock<ICacheService>();
        cache.Setup(c => c.GetAuthorizationRequest("code")).ReturnsAsync(new AuthorizationRequest());
        var logger = new Mock<ILogger<AuthorizeController>>();
        var idpListService = new Mock<IFedMasterIdpListService>();
        var idpEntry = new IdpEntry() { iss = "https://sectoridp" };
        idpListService.Setup(l => l.GetIdpListAsync()).ReturnsAsync(new List<IdpEntry>
            { idpEntry } );
        var cnt = new AuthorizeController(authOptions.Object, cache.Object, secTlsClient, idpListService.Object,
            logger.Object);
        var resp = await cnt.Login("code", idpEntry.id);
        var uri = new Uri((resp as RedirectResult)?.Url);
        var query = HttpUtility.ParseQueryString(uri.Query);   
        Assert.IsTrue(uri.AbsoluteUri.StartsWith("https://secauth/auth"));
        Assert.AreEqual("urn:any",query["request_uri"]);
        Assert.AreEqual("https://issuer",query["client_id"]);
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