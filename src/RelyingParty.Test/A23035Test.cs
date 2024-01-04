using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Com.Bayoomed.TelematikFederation;
using Com.Bayoomed.TelematikFederation.Controllers.OidcAuthServer;
using Com.Bayoomed.TelematikFederation.OidcRequest;
using Com.Bayoomed.TelematikFederation.Services;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Moq;

namespace RelyingParty.Test;

[TestClass]
public class A23035Test
{
    /// <summary>
    ///     A_23035 - pseudonymes Attribut "sub"
    ///     Fachdienste MÜSSEN das Attribut sub als pseudonyme ID des Versicherten in Kombination mit dem iss des ausstellenden
    ///     IDP verwenden, da dieses nur eineindeutig je IDP ist.
    /// </summary>
    [TestMethod]
    public async Task A23035_SubClaimContainsSubAndIssFromSecIdp()
    {
        var options = new Mock<IOptions<AuthServerOptions>>();
        options.Setup(options => options.Value).Returns(new AuthServerOptions
        {
            Issuer = "issuer",
            SignPrivKey = ECDsa.Create().ExportECPrivateKeyPem(),
            Clients = new[]
            {
                new OidcClient
                {
                    ClientId = "client_id",
                    ClientSecret = "client_secret",
                    RedirectUris = new[] { "redirect_uri" }
                }
            }
        });
        var cache = new Mock<ICacheService>();
        cache.Setup(c => c.GetAndRemoveAuthorizationRequest(It.IsAny<string>()))
            .ReturnsAsync(new AuthorizationRequest
            {
                client_id = "client_id",
                redirect_uri = "redirect_uri",
                nonce = "nonce",
                code_challenge = Base64UrlEncoder.Encode(SHA256.HashData("code_verifier"u8.ToArray()))
            });
        cache.Setup(c => c.GetAndRemoveIdTokenFromSectorIdP(It.IsAny<string>())).ReturnsAsync(new JwtPayload(new Claim[]
        {
            new("iss", "fakeiss"),
            new("sub", "fakesub"),
            new("urn:telematik:claims:id", "fakeKvnr")
        }));
        var logger = new Mock<ILogger<TokenController>>();
        var tokenCnt = new TokenController(options.Object, cache.Object, logger.Object, new TokenRequestValidator(options.Object));

        var result = await tokenCnt.Post(new TokenRequest
        {
            code = "code",
            client_id = "client_id",
            client_secret = "client_secret",
            grant_type = "authorization_code",
            redirect_uri = "redirect_uri",
            code_verifier = "code_verifier"
        });

        var jsonResult = (JsonResult)result;
        var tokenResponse = (TokenResponse)jsonResult.Value;
        var idtoken = new JwtSecurityTokenHandler().ReadToken(tokenResponse.id_token) as JwtSecurityToken;
        Assert.AreEqual(idtoken.Subject,
            Base64UrlEncoder.Encode(SHA256.HashData("fakesubfakeiss"u8.ToArray())));
    }
}