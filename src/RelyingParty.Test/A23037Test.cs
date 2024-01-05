using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
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
public class A23037Test
{
    /// <summary>
    ///     A_23037 - Robustheit bei fehlenden Daten
    ///     Sind einzelne claims des angefragten scopes nicht im ID_TOKEN enthalten oder leer, weil
    ///     beispielsweise der Nutzer die Herausgabe verweigert oder Daten nicht hinterlegt wurden,
    ///     so MUSS der Fachdienst das ID_TOKEN trotzdem akzeptieren und innerhalb der
    ///     Fachanwendung geeignet reagieren.
    /// </summary>
    [TestMethod]
    public async Task A23037_MissingKvnrClaimFromSecIdp()
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
        //no kvnr claim from secidp
        cache.Setup(c => c.GetAndRemoveIdTokenFromSectorIdP(It.IsAny<string>())).ReturnsAsync(new JwtPayload(new Claim[]
        {
            new("iss", "fakeiss"),
            new("sub", "fakesub"),
            //new("urn:telematik:claims:id", "fakeKvnr")
        }));
        var logger = new Mock<ILogger<TokenController>>();
        var tokenCnt = new TokenController(options.Object, cache.Object, logger.Object,
            new TokenRequestValidator(options.Object));

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
        var kvnrClaim = idtoken.Claims.FirstOrDefault(c=>c.Type == "urn:telematik:claims:id");
        Assert.IsNull(kvnrClaim);
    }
    
    /// <summary>
    ///     A_23037 - Robustheit bei fehlenden Daten
    ///     Sind einzelne claims des angefragten scopes nicht im ID_TOKEN enthalten oder leer, weil
    ///     beispielsweise der Nutzer die Herausgabe verweigert oder Daten nicht hinterlegt wurden,
    ///     so MUSS der Fachdienst das ID_TOKEN trotzdem akzeptieren und innerhalb der
    ///     Fachanwendung geeignet reagieren.
    /// </summary>
    [TestMethod]
    public async Task A23037_ExistingKvnrClaimFromSecIdp()
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
        //kvnr claim from secidp
        cache.Setup(c => c.GetAndRemoveIdTokenFromSectorIdP(It.IsAny<string>())).ReturnsAsync(new JwtPayload(new Claim[]
        {
            new("iss", "fakeiss"),
            new("sub", "fakesub"),
            new("urn:telematik:claims:id", "fakeKvnr")
        }));
        var logger = new Mock<ILogger<TokenController>>();
        var tokenCnt = new TokenController(options.Object, cache.Object, logger.Object,
            new TokenRequestValidator(options.Object));

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
        var kvnrClaim = idtoken.Claims.FirstOrDefault(c=>c.Type == "urn:telematik:claims:id");
        Assert.IsNotNull(kvnrClaim);
        Assert.AreEqual("fakeKvnr", kvnrClaim.Value);
    }
}