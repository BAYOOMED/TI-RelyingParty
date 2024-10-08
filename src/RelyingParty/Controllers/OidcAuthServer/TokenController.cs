using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Com.Bayoomed.TelematikFederation.OidcRequest;
using Com.Bayoomed.TelematikFederation.OidcResponse;
using Com.Bayoomed.TelematikFederation.Services;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

namespace Com.Bayoomed.TelematikFederation.Controllers.OidcAuthServer;

public class TokenController(
    IOptions<AuthServerOptions> options,
    ICacheService cache,
    ILogger<TokenController> logger,
    ITokenRequestValidator requestValidator) : Controller
{
    private readonly string _issuer = options.Value.Issuer;

    private readonly string _signPrivKey = options.Value.SignPrivKey;

    /// <summary>
    ///     The token endpoint of the auth server. Exchange the code for an id_token and access_token.
    /// </summary>
    /// <param name="tokenRequest"></param>
    /// <param name="authorization"></param>
    /// <returns></returns>
    [HttpPost]
    public async Task<IActionResult> Post(TokenRequest tokenRequest,
        [FromHeader(Name = "Authorization")] string authorization)
    {
        logger.LogDebug("token request: {@Request}", tokenRequest);
        if (!string.IsNullOrEmpty(authorization))
        {
            logger.LogDebug("using basic auth header");
            //parse basic auth header
            var parts = authorization.Split(' ');
            if (parts.Length != 2 || parts[0] != "Basic")
                return TokenError(OidcError.invalid_request, tokenRequest, "invalid basic auth header");
            var creds = Encoding.UTF8.GetString(Convert.FromBase64String(parts[1])).Split(':');
            if (creds.Length != 2)
                return TokenError(OidcError.invalid_request, tokenRequest, "invalid basic auth header");
            tokenRequest.client_id = creds[0];
            tokenRequest.client_secret = creds[1];
        }

        var authRequest = await cache.GetAndRemoveAuthorizationRequest(tokenRequest.code);
        var secIdToken = await cache.GetAndRemoveIdTokenFromSectorIdP(tokenRequest.code);
        if (secIdToken == null || authRequest == null)
            return TokenError(OidcError.invalid_grant, tokenRequest, "cache miss - session expired");
        var (error, msg) = requestValidator.ValidateRequest(tokenRequest, authRequest);
        if (error != null)
            return TokenError(error.Value, tokenRequest, msg);
        using var ecdsa = ECDsa.Create();
        ecdsa.ImportFromPem(_signPrivKey);
        var secKey = new ECDsaSecurityKey(ecdsa);
        secKey.KeyId = Base64UrlEncoder.Encode(secKey.ComputeJwkThumbprint());
        var signingCredentials = new SigningCredentials(secKey, SecurityAlgorithms.EcdsaSha256)
        {
            CryptoProviderFactory = new CryptoProviderFactory { CacheSignatureProviders = false }
        };
        var sub = Base64UrlEncoder.Encode(SHA256.HashData(Encoding.UTF8.GetBytes(secIdToken.Sub + secIdToken.Iss)));
        var claims = new[]
        {
            new Claim(JwtRegisteredClaimNames.Sub, sub),
            new Claim(JwtRegisteredClaimNames.Iat, EpochTime.GetIntDate(DateTime.UtcNow).ToString(),
                ClaimValueTypes.Integer64),
            new Claim(JwtRegisteredClaimNames.Nonce, authRequest.nonce)
        }.Union(secIdToken.Claims.Where(c => c.Type.StartsWith("urn:telematik:claims:") || c.Type == "birthdate"));
        var token = new JwtSecurityToken(_issuer, authRequest.client_id, claims, DateTime.UtcNow,
            DateTime.UtcNow.AddMinutes(15), signingCredentials);
        var idToken = new JwtSecurityTokenHandler().WriteToken(token);
        var accessToken = Base64UrlEncoder.Encode(RandomNumberGenerator.GetBytes(32));
        //save it, so we can use it for userInfo endpoint
        await cache.AddIdToken(accessToken, token.Payload);
        logger.LogDebug("id_token from auth: {@IdToken}", idToken);
        return Json(new TokenResponse { id_token = idToken, access_token = accessToken, token_type = "Bearer" });
    }

    private IActionResult TokenError(OidcError error, TokenRequest request, string? details = null)
    {
        logger.Log(error == OidcError.server_error ? LogLevel.Error : LogLevel.Warning,
            "oidc error: {Error}, details: {Details}, token-request: {@Request}", error, details, request);
        return error is OidcError.invalid_client ? Unauthorized(error.ToString()) : BadRequest(error.ToString());
    }
}