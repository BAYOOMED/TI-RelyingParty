using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using Com.Bayoomed.TelematikFederation.Services;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using JsonClaimValueTypes = Microsoft.IdentityModel.JsonWebTokens.JsonClaimValueTypes;
using JwtRegisteredClaimNames = Microsoft.IdentityModel.JsonWebTokens.JwtRegisteredClaimNames;

namespace Com.Bayoomed.TelematikFederation.Controllers.OidcFederation;

public class JwksController(IOptions<OidcFedOptions> options, ITlsClientCertificateService certService) : ControllerBase
{
    private readonly string _encPrivKey = options.Value.EncPrivKey;
    private readonly string _issuer = options.Value.Issuer;
    private readonly string _signPrivKey = options.Value.SignPrivKey;

    /// <summary>
    /// Returns the signed Jwks of the Relying Party (OIDC Federation)
    /// </summary>
    /// <returns></returns>
    [HttpGet]
    public ContentResult Get()
    {
        using var ecdsa = ECDsa.Create();
        ecdsa.ImportFromPem(_signPrivKey);
        var secKey = new ECDsaSecurityKey(ecdsa);
        secKey.KeyId = Base64UrlEncoder.Encode(secKey.ComputeJwkThumbprint());

        var signingCredentials = new SigningCredentials(secKey, SecurityAlgorithms.EcdsaSha256)
        {
            CryptoProviderFactory = new CryptoProviderFactory { CacheSignatureProviders = false }
        };
        var header = new JwtHeader(signingCredentials, null, "jwk-set+json");
        var ecEnc = ECDsa.Create();
        ecEnc.ImportFromPem(_encPrivKey);

        var claims = new[]
        {
            new Claim(JwtRegisteredClaimNames.Iat, EpochTime.GetIntDate(DateTime.UtcNow).ToString(),
                ClaimValueTypes.Integer64),
            new Claim(JwtRegisteredClaimNames.Sub, _issuer,
                ClaimValueTypes.String),
            new Claim("keys", JsonSerializer.Serialize(new[]
            {
                CreateJwk(ecdsa),
                CreateJwk(ecEnc, "enc"),
                CreateJwk(certService.GetCertPem())
            }).RemoveEmptyArrayProperties(), JsonClaimValueTypes.JsonArray)
        };
        var payload = new JwtPayload(_issuer, null, claims, null,
            null);

        var token = new JwtSecurityToken(header, payload);
        return new ContentResult
        {
            Content = new JwtSecurityTokenHandler().WriteToken(token),
            StatusCode = (int)HttpStatusCode.OK,
            ContentType = "application/jwk-set+json"
        };
    }


    private JsonWebKey CreateJwk(ECDsa key, string use = "sig")
    {
        using var ecdsa = ECDsa.Create();
        ecdsa.ImportFromPem(key.ExportSubjectPublicKeyInfoPem());
        var secKey = new ECDsaSecurityKey(ecdsa);
        secKey.KeyId = Base64UrlEncoder.Encode(secKey.ComputeJwkThumbprint());

        var jwk = JsonWebKeyConverter.ConvertFromECDsaSecurityKey(secKey);
        jwk.Use = use;
        jwk.Alg = use == "sig" ? SecurityAlgorithms.EcdsaSha256 : SecurityAlgorithms.EcdhEs;
        return jwk;
    }

    private JsonWebKey CreateJwk(string pemCert, string use = "sig")
    {
        using var cert = X509CertificateLoader.LoadCertificate(Encoding.UTF8.GetBytes(pemCert));
        var secKey = new X509SecurityKey(cert);

        var jwk = JsonWebKeyConverter.ConvertFromX509SecurityKey(secKey);
        jwk.Use = use;
        var pubJwk = CreateJwk(cert.GetECDsaPublicKey() ?? throw new InvalidOperationException());
        jwk.Alg = use == "sig" ? SecurityAlgorithms.EcdsaSha256 : SecurityAlgorithms.EcdhEs;
        jwk.Crv = pubJwk.Crv;
        jwk.X = pubJwk.X;
        jwk.Y = pubJwk.Y;
        jwk.Kty = pubJwk.Kty;

        return jwk;
    }
}