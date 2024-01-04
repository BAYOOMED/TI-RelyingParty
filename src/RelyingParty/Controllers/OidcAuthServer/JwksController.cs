using System.Security.Cryptography;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

namespace Com.Bayoomed.TelematikFederation.Controllers.OidcAuthServer;

public class JwksAuthController(IOptions<AuthServerOptions> options) : Controller
{
    private readonly string _signPrivKey = options.Value.SignPrivKey;
    
    /// <summary>
    /// Return the Jwks of the Auth Server (only signature public key is included)
    /// </summary>
    /// <returns></returns>
    [HttpGet]
    public JsonResult Get()
    {
        using var ecdsa = ECDsa.Create();
        ecdsa.ImportFromPem(_signPrivKey);
        ecdsa.ImportFromPem(ecdsa.ExportSubjectPublicKeyInfoPem());
        var secKey = new ECDsaSecurityKey(ecdsa);
        secKey.KeyId = Base64UrlEncoder.Encode(secKey.ComputeJwkThumbprint());
        var jwk = JsonWebKeyConverter.ConvertFromECDsaSecurityKey(secKey);
        jwk.Use = "sig";
        var keySet = new JsonWebKeySet();
        keySet.Keys.Add(jwk);
        return Json(keySet);
    }
}