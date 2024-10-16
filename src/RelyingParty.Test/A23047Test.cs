using Com.Bayoomed.TelematikFederation;
using Com.Bayoomed.TelematikFederation.Controllers.OidcAuthServer;
using Com.Bayoomed.TelematikFederation.OidcRequest;
using Com.Bayoomed.TelematikFederation.Services;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Moq;

namespace RelyingParty.Test;

[TestClass]
public class A23047Test
{
    /// <summary>
    ///     A_23047 - Endpunkt für OAuth 2.0 Authorization Endpoint
    ///     Authorization-Server MÜSSEN einen OAuth 2.0 Authorization Endpunkt anbieten um Authorization Requests mit PKCE/Code
    ///     Challenge entsprechend https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.1 und
    ///     https://datatracker.ietf.org/doc/html/rfc7636#section-4.3 zu akzeptieren und zu verarbeiten.
    /// </summary>
    [TestMethod]
    public async Task A23047_CheckAuthEndpointCodeAndPkce()
    {
        var options = new Mock<IOptions<AuthServerOptions>>();
        options.Setup(o => o.Value).Returns(new AuthServerOptions
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
        cache.Setup(c => c.AddAuthorizationRequest(It.IsAny<AuthorizationRequest>(),It.IsAny<string>())).ReturnsAsync("acode");
        var logger = new Mock<ILogger<AuthorizeController>>();
        var parService = new Mock<ISectorIdPmTlsService>();
        var idpListService = new Mock<IFedMasterIdpListService>();
        var cnt = new AuthorizeController(options.Object, cache.Object, parService.Object, idpListService.Object, logger.Object);
        var resp = await cnt.Authorize(new AuthorizationRequest
        {
            client_id = "client",
            redirect_uri = "https://redirect",
            response_type = "code",
            scope = "openid",
            code_challenge = "challenge",
            code_challenge_method = "S256",
            nonce = "nonce",
            state = "state"
        });
        Assert.IsInstanceOfType(resp, typeof(RedirectResult));
        Assert.IsTrue((resp as RedirectResult).Url.Contains("code=acode"));
    }
}