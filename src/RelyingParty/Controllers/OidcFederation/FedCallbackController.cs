using System.IdentityModel.Tokens.Jwt;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Web;
using Com.Bayoomed.TelematikFederation.OidcRequest;
using Com.Bayoomed.TelematikFederation.OidcResponse;
using Com.Bayoomed.TelematikFederation.Services;
using Jose;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

namespace Com.Bayoomed.TelematikFederation.Controllers.OidcFederation;

public class FedCallbackController
(ICacheService cache, IOptions<OidcFedOptions> options, IOptions<AuthServerOptions> authOptions,
    ISectorIdPEntityStatementService sectorIdpEsService, ISectorIdPmTlsService sectorIdPmTlsService,
    ILogger<FedCallbackController> logger) : Controller
{
    private readonly string _authIss = authOptions.Value.Issuer;
    private readonly string _encPrivKey = options.Value.EncPrivKey;
    private readonly string _iss = options.Value.Issuer;

    /// <summary>
    ///     Called after the user has authenticated at the sector idp. Processes the external error or code and exchanges it
    ///     for a code from the auth server.
    /// </summary>
    /// <param name="code"></param>
    /// <param name="state"></param>
    /// <param name="errorCode"></param>
    /// <param name="errorDescription"></param>
    /// <returns></returns>
    /// <exception cref="Exception"></exception>
    [HttpGet]
    public async Task<IActionResult> Callback(string? code, string state,
        [FromQuery(Name = "error_code")] string? errorCode,
        [FromQuery(Name = "error_description")] string? errorDescription)
    {
        var par = await cache.GetAndRemoveParResponse(state);
        var authRequest = await cache.GetAndRemoveAuthorizationRequest(state);
        if (authRequest == null || par == null)
        {
            logger.LogWarning("session expired. Request: {Code} {State} {ErrorCode} {ErrorDescription}", code, state,
                errorCode, errorDescription);
            return BadRequest("session expired");
        }

        if (!string.IsNullOrEmpty(errorCode) || string.IsNullOrEmpty(code))
        {
            logger.Log(errorCode == OidcError.access_denied.ToString() ? LogLevel.Warning : LogLevel.Error,
                "error from sector idp: {Code}, {Error}, {Description}", code, errorCode,
                errorDescription);
            return ErrorRedirect(errorCode, authRequest);
        }

        var tokenRequest = new TokenRequest
        {
            grant_type = "authorization_code",
            code = code,
            code_verifier = par.CodeVerifier,
            client_id = _iss,
            redirect_uri = $"{_iss}/cb"
        };

        try
        {
            var esSec = await sectorIdpEsService.GetSectorIdPEntityStatement(par.SecIdpIss);
            var rawIdToken = await sectorIdPmTlsService.SendTokenRequest(tokenRequest, esSec.GetTokenEndpoint()!);
            logger.LogDebug("rawIdToken: {RawIdToken}", rawIdToken);
            var decryptedToken = DecryptToken(rawIdToken);
            JwtSecurityToken validatedToken;
            try
            {
                validatedToken = await ValidateToken(decryptedToken, par.SecIdpIss);
            }
            catch (SecurityTokenInvalidSignatureException e)
            {
                logger.LogInformation(e, "Signature verification failed - Trying to refresh jwks");
                validatedToken = await ValidateToken(decryptedToken, par.SecIdpIss, true);
            }

            var idToken = validatedToken.Payload;
            if (idToken.Nonce == null || idToken.Nonce != par.Request.nonce)
                throw new Exception("nonce mismatch");
            if (idToken["urn:telematik:claims:id"] == null) throw new Exception("missing kvnr claim in id token");
            if (idToken.Acr != "gematik-ehealth-loa-high")
                throw new Exception("acr value mismatch");

            var newCode = await cache.AddAuthorizationRequest(authRequest);
            await cache.AddIdTokenFromSectorIdP(newCode, idToken);
            var redirectUri = new UriBuilder(authRequest.redirect_uri);
            var query = HttpUtility.ParseQueryString(redirectUri.Query);
            query["response_type"] = authRequest.response_type;
            query["state"] = authRequest.state;
            query["code"] = newCode;
            query["iss"] = _authIss;
            redirectUri.Query = query.ToString();
            logger.LogDebug("token iss: {Token}", decryptedToken);
            return Redirect(redirectUri.Uri.ToString());
        }
        catch (Exception e)
        {
            logger.LogError(e, "code exchange error: {@AuthRequest} {@TokenRequest}", par, tokenRequest);
            return ErrorRedirect(OidcError.server_error.ToString(), authRequest);
        }
    }

    private async Task<JwtSecurityToken> ValidateToken(string rawIdToken, string secIdpIss, bool forceRefresh = false)
    {
        var keys = (await sectorIdpEsService.GetSectorIdPJwks(secIdpIss, forceRefresh)).Keys;
        new JwtSecurityTokenHandler().ValidateToken(rawIdToken, new TokenValidationParameters
        {
            ValidateAudience = true,
            ValidAudience = _iss,
            ValidateIssuer = true,
            ValidIssuer = secIdpIss,
            IssuerSigningKeys = keys,
            ValidateLifetime = true
        }, out var validatedToken);
        return (validatedToken as JwtSecurityToken)!;
    }

    private IActionResult ErrorRedirect(string? errorCode, AuthorizationRequest authRequest)
    {
        var ru = new UriBuilder(authRequest.redirect_uri);
        var eq = HttpUtility.ParseQueryString(ru.Query);
        eq["iss"] = _authIss;
        eq["error"] = Enum.TryParse<OidcError>(errorCode, out var error)
            ? error.ToString()
            : OidcError.server_error.ToString();
        eq["state"] = authRequest.state;
        ru.Query = eq.ToString();
        return Redirect(ru.ToString());
    }

    private JsonWebKey GetDecryptionKey()
    {
        using var ecdsa = ECDsa.Create();
        ecdsa.ImportFromPem(_encPrivKey);
        var secKey = new ECDsaSecurityKey(ecdsa);
        secKey.KeyId = Base64UrlEncoder.Encode(secKey.ComputeJwkThumbprint());
        return JsonWebKeyConverter.ConvertFromECDsaSecurityKey(secKey);
    }

    private string DecryptToken(string rawToken)
    {
        var jwk = GetDecryptionKey();
        var joseJwk = new Jwk(jwk.Crv, jwk.X, jwk.Y, jwk.D)
        {
            KeyId = jwk.Kid
        };
        return JWT.Decode(rawToken, joseJwk, new JwtSettings());
    }
}