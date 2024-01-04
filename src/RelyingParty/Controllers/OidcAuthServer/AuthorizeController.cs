using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Web;
using Com.Bayoomed.TelematikFederation.OidcRequest;
using Com.Bayoomed.TelematikFederation.OidcResponse;
using Com.Bayoomed.TelematikFederation.Services;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;

namespace Com.Bayoomed.TelematikFederation.Controllers.OidcAuthServer;

public class AuthorizeController(IOptions<AuthServerOptions> options, ICacheService cache,
    ISectorIdPmTlsService parService, IFedMasterIdpListService idpListService,
    ILogger<AuthorizeController> logger) : Controller
{
    private readonly IList<OidcClient> _clients = options.Value.Clients;
    private readonly string _iss = options.Value.Issuer;

    /// <summary>
    ///     Authorize Endpoint of the Auth Server
    /// </summary>
    /// <param name="authorizationRequest"></param>
    /// <returns></returns>
    public async Task<IActionResult> Authorize(AuthorizationRequest authorizationRequest)
    {
        //the magic begins here!
        //validate input parameters
        var client = _clients.FirstOrDefault(c => c.ClientId == authorizationRequest.client_id);
        if (client == null)
            return AuthorizeError(OidcError.invalid_client, authorizationRequest);
        if (!client.RedirectUris.Contains(authorizationRequest.redirect_uri))
            return AuthorizeError(OidcError.redirect_uri_mismatch, authorizationRequest);
        if (authorizationRequest.response_type != "code")
            return AuthorizeError(OidcError.unsupported_response_type, authorizationRequest);
        if (authorizationRequest.scope != "openid")
            return AuthorizeError(OidcError.invalid_scope, authorizationRequest);
        if (string.IsNullOrEmpty(authorizationRequest.code_challenge))
            return AuthorizeError(OidcError.invalid_request, authorizationRequest, "code challenge missing");
        if (authorizationRequest.code_challenge_method != "S256")
            return AuthorizeError(OidcError.invalid_request, authorizationRequest,
                "code challenge method not supported");
        //store the authorizationRequest (using a random key)
        var code = await cache.AddAuthorizationRequest(authorizationRequest);

        //check if we have a login_hint and skip login web page
        if (authorizationRequest.login_hint != null)
            return await Login(code, authorizationRequest.login_hint);
        //show initial login page
        return Redirect($"{new Uri(_iss).LocalPath}/static/{client.LoginPagePath}?code={code}");
    }

    private IActionResult AuthorizeError(OidcError error, AuthorizationRequest request, string? details = null)
    {
        logger.Log(error == OidcError.server_error ? LogLevel.Error : LogLevel.Warning,
            "oidc error: {Error}, details: {Details}, request: {@Request}", error, details, request);
        if (error is OidcError.invalid_client or OidcError.redirect_uri_mismatch)
            return BadRequest(error.ToString());
        var ru = new UriBuilder(request.redirect_uri);
        var query = HttpUtility.ParseQueryString(ru.Query);
        query["iss"] = _iss;
        query["error"] = error.ToString();
        query["state"] = request.state;
        ru.Query = query.ToString();
        return Redirect(ru.Uri.ToString());
    }

    /// <summary>
    ///     This is the callback from the login page. It will be called with a code and the idp id. And start the OIDC fed flow
    /// </summary>
    /// <param name="code"></param>
    /// <param name="idpid"></param>
    /// <returns></returns>
    [HttpPost]
    public async Task<IActionResult> Login(string code, string idpid)
    {
        var authRequest = await cache.GetAndRemoveAuthorizationRequest(code);
        if (authRequest == null)
            return AuthorizeError(OidcError.invalid_client, new AuthorizationRequest(), "cache miss - session expired");

        //store the new code & request
        var newCode = await cache.AddAuthorizationRequest(authRequest);
        try
        {
            // actual flow starts here
            var secIdp = (await idpListService.GetIdpListAsync())?.FirstOrDefault(e => e.id == idpid);
            if (secIdp == null)
                return BadRequest();
            var parResponse = await parService.SendPushedAuthorizationRequest(secIdp.iss, newCode);
            // we need this later to get the token
            await cache.AddParResponse(newCode, parResponse);
            return Redirect(parResponse.RedirectUri);
        }
        catch (Exception e)
        {
            return AuthorizeError(OidcError.server_error, authRequest, e.ToString());
        }
    }

    /// <summary>
    /// This is meant for testing only. No interaction with TI. Instantly returns a fake id_token
    /// </summary>
    /// <param name="code"></param>
    /// <param name="idpid"></param>
    /// <returns></returns>
    [HttpPost]
    public async Task<IActionResult> FakeLogin(string code)
    {
        var authRequest = await cache.GetAndRemoveAuthorizationRequest(code);
        if (authRequest == null)
            return AuthorizeError(OidcError.invalid_client, new AuthorizationRequest(), "cache miss - session expired");

        //store the new code & request
        var newCode = await cache.AddAuthorizationRequest(authRequest);
        //shortcut! we need to start oidc fed login here
        var fakePayload = new JwtPayload("fakeiss", "none", new Claim[]
        {
            new("sub", "fakesub"),
            new("urn:telematik:claims:id", "fakeKvnr")
        }, DateTime.UtcNow, DateTime.UtcNow.AddMinutes(15));

        await cache.AddIdTokenFromSectorIdP(newCode, fakePayload);
        var redirectUri = new UriBuilder(authRequest.redirect_uri);
        var query = HttpUtility.ParseQueryString(redirectUri.Query);
        query["response_type"] = authRequest.response_type;
        query["state"] = authRequest.state;
        query["code"] = newCode;
        redirectUri.Query = query.ToString();

        return Redirect(redirectUri.Uri.ToString());
    }
}