using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text.Json;
using Com.Bayoomed.TelematikFederation.OidcResponse;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using JsonClaimValueTypes = Microsoft.IdentityModel.JsonWebTokens.JsonClaimValueTypes;
using JwtRegisteredClaimNames = Microsoft.IdentityModel.JsonWebTokens.JwtRegisteredClaimNames;

namespace Com.Bayoomed.TelematikFederation.Controllers.OidcFederation;

public class EntityStatementController(IOptions<OidcFedOptions> options) : ControllerBase
{
    private readonly string _clientName = options.Value.ClientName;
    private readonly string _fedMaster = options.Value.FederationMaster;
    private readonly string _issuer = options.Value.Issuer;
    private readonly string _scope = options.Value.Scope;
    private readonly string _signPrivKey = options.Value.SignPrivKey;

    /// <summary>
    ///     Returns the signed Entity Statement of the Relying Party (OIDC Federation)
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
        var header = new JwtHeader(signingCredentials, null,
            "entity-statement+jwt");
        var claims = new[]
        {
            new Claim(JwtRegisteredClaimNames.Iat, EpochTime.GetIntDate(DateTime.UtcNow).ToString(),
                ClaimValueTypes.Integer64),
            new Claim(JwtRegisteredClaimNames.Sub, _issuer,
                ClaimValueTypes.String),
            new Claim("jwks", JsonSerializer.Serialize(CreateJwks(ecdsa)).RemoveEmptyArrayProperties(), JsonClaimValueTypes.Json),
            new Claim("authority_hints", JsonSerializer.Serialize(new[] { _fedMaster }),
                JsonClaimValueTypes.JsonArray),
            new Claim("metadata", JsonSerializer.Serialize(
                new EntityStatementJwtMetadata(_issuer, _clientName, _scope)
            ).RemoveEmptyArrayProperties(), JsonClaimValueTypes.Json)
        };
        var payload = new JwtPayload(_issuer, null, claims, null,
            DateTime.UtcNow.AddMinutes(120));

        var token = new JwtSecurityToken(header, payload);
        return new ContentResult
        {
            Content = new JwtSecurityTokenHandler().WriteToken(token),
            StatusCode = (int)HttpStatusCode.OK,
            ContentType = "application/entity-statement+jwt"
        };
    }


    private JsonWebKeySet CreateJwks(ECDsa key)
    {
        using var ecdsa = ECDsa.Create();
        ecdsa.ImportFromPem(key.ExportSubjectPublicKeyInfoPem());
        var secKey = new ECDsaSecurityKey(ecdsa);
        secKey.KeyId = Base64UrlEncoder.Encode(secKey.ComputeJwkThumbprint());
        var jwk = JsonWebKeyConverter.ConvertFromECDsaSecurityKey(secKey);
        jwk.Use = "sig";
        jwk.Alg = SecurityAlgorithms.EcdsaSha256;
        var jwks = new JsonWebKeySet();
        jwks.Keys.Add(jwk);
        return jwks;
    }
}