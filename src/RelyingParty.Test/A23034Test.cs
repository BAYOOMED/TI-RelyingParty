using System.IdentityModel.Tokens.Jwt;
using System.Security.Cryptography;
using System.Text.Json;
using Com.Bayoomed.TelematikFederation;
using Com.Bayoomed.TelematikFederation.Controllers.OidcFederation;
using Com.Bayoomed.TelematikFederation.Services;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Moq;

namespace RelyingParty.Test;

[TestClass]
public class A23034Test
{
    /// <summary>
    ///     Authorization-Server MÜSSEN über sich ein, ES256 signiertes, Entity Statement gemäß [ OpenID Connect Federation
    ///     1.0#rfc.section.6] unter ".well-known/openid-federation" veröffentlichen. Das Entity Statement ist maximal 24h
    ///     gültig.
    /// </summary>
    [TestMethod]
    public void A23034_TestEntityStatementExpiration()
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
        
        Assert.IsTrue(token.ValidTo <= DateTime.UtcNow.AddHours(24));
    }
}