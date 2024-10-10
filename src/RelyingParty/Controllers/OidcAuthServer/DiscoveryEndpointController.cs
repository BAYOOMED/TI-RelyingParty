using Com.Bayoomed.TelematikFederation.OidcResponse;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;

namespace Com.Bayoomed.TelematikFederation.Controllers.OidcAuthServer;

public class DiscoveryEndpointController(IOptions<AuthServerOptions> options) : Controller
{
    private readonly string _issuer = options.Value.Issuer;

    /// <summary>
    ///     returns the OIDC Discovery Document of the Auth Server
    /// </summary>
    /// <returns></returns>
    [HttpGet]
    public JsonResult Get()
    {
        var response = new DiscoveryResponse
        {
            issuer = _issuer,
            authorization_endpoint = $"{_issuer}/auth/Authorize",
            userinfo_endpoint = $"{_issuer}/auth/UserInfo",
            token_endpoint = $"{_issuer}/auth/Token",
            token_endpoint_auth_methods_supported =
                new[] { "client_secret_post", "private_key_jwt", "client_secret_basic" },
            response_types_supported = new[] { "code" },
            subject_types_supported = new[] { "public", "pairwise" },
            id_token_signing_alg_values_supported = new[] { "ES256" },
            jwks_uri = $"{_issuer}/jwks.json",
            scopes_supported = new[] { "openid" },
            claims_supported = new[]
            {
                "sub", "iss"
            },
            claims_parameter_supported = false,
            code_challenge_methods_supported = new[] { "S256" }
        };

        return Json(response);
    }
}