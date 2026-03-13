using System.IdentityModel.Tokens.Jwt;
using System.Text.Json;
using Com.Bayoomed.TelematikFederation;
using Com.Bayoomed.TelematikFederation.OidcResponse;
using Com.Bayoomed.TelematikFederation.Services;
using Microsoft.Extensions.Options;
using Moq;

namespace RelyingParty.Test;

[TestClass]
public class A23030Test
{
    private Mock<ISectorIdPEntityStatementService> SetupSecEs()
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
        return secEs;
    }

    private static Mock<IOptions<OidcFedOptions>> SetupOptions()
    {
        var options = new Mock<IOptions<OidcFedOptions>>();
        options.Setup(o => o.Value).Returns(new OidcFedOptions
        {
            Issuer = "https://issuer"
        });
        return options;
    }

    /// <summary>
    ///     A_23030 - Erzwingen einer Authentisierung des Nutzers
    ///     Fachdienste KÖNNEN eine Benutzerauthentifizierung erzwingen via prompt=login im PAR.
    /// </summary>
    [TestMethod]
    public async Task A23030_PromptLoginIsForwardedInPar()
    {
        var secEs = SetupSecEs();
        var options = SetupOptions();
        var handlerMock =
            new A23004Test.HttpMessageHandlerMock(new StringContent(JsonSerializer.Serialize(new AuthorizationResponse())));
        var secTlsClient = new SectorIdPmTlsService(secEs.Object, options.Object, new HttpClient(handlerMock));
        _ = await secTlsClient.SendPushedAuthorizationRequest("https://sectoridp", "state", null, prompt: "login");
        var req = handlerMock.Request!.Content as FormUrlEncodedContent;
        var content = await req!.ReadAsStringAsync();
        Assert.IsTrue(content.Contains("prompt=login"), $"Expected prompt=login in PAR content: {content}");
    }

    /// <summary>
    ///     A_23030 - Erzwingen einer Authentisierung des Nutzers
    ///     Fachdienste KÖNNEN eine Benutzerauthentifizierung erzwingen via max_age=0 im PAR.
    /// </summary>
    [TestMethod]
    public async Task A23030_MaxAgeZeroIsForwardedInPar()
    {
        var secEs = SetupSecEs();
        var options = SetupOptions();
        var handlerMock =
            new A23004Test.HttpMessageHandlerMock(new StringContent(JsonSerializer.Serialize(new AuthorizationResponse())));
        var secTlsClient = new SectorIdPmTlsService(secEs.Object, options.Object, new HttpClient(handlerMock));
        _ = await secTlsClient.SendPushedAuthorizationRequest("https://sectoridp", "state", null, maxAge: "0");
        var req = handlerMock.Request!.Content as FormUrlEncodedContent;
        var content = await req!.ReadAsStringAsync();
        Assert.IsTrue(content.Contains("max_age=0"), $"Expected max_age=0 in PAR content: {content}");
    }

    /// <summary>
    ///     A_23030 - Wenn prompt und max_age nicht gesetzt sind, sollen sie nicht im PAR auftauchen.
    /// </summary>
    [TestMethod]
    public async Task A23030_PromptAndMaxAgeOmittedWhenNotSet()
    {
        var secEs = SetupSecEs();
        var options = SetupOptions();
        var handlerMock =
            new A23004Test.HttpMessageHandlerMock(new StringContent(JsonSerializer.Serialize(new AuthorizationResponse())));
        var secTlsClient = new SectorIdPmTlsService(secEs.Object, options.Object, new HttpClient(handlerMock));
        _ = await secTlsClient.SendPushedAuthorizationRequest("https://sectoridp", "state", null);
        var req = handlerMock.Request!.Content as FormUrlEncodedContent;
        var content = await req!.ReadAsStringAsync();
        Assert.IsFalse(content.Contains("prompt"), $"prompt should not be in PAR content when not set: {content}");
        Assert.IsFalse(content.Contains("max_age"), $"max_age should not be in PAR content when not set: {content}");
    }
}
