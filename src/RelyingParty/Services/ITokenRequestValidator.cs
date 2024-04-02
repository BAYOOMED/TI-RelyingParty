using Com.Bayoomed.TelematikFederation.OidcRequest;
using Com.Bayoomed.TelematikFederation.OidcResponse;

namespace Com.Bayoomed.TelematikFederation.Services;

/// <summary>
/// Interace for Validation of OIDC token requests
/// </summary>
public interface ITokenRequestValidator
{
    /// <summary>
    /// Validate the tokenRequest
    /// </summary>
    /// <param name="tokenRequest">the token request</param>
    /// <param name="authRequest">the initial authentication request</param>
    /// <returns>error and message in case the validation fails, null otherwise</returns>
    (OidcError? error, string? message) ValidateRequest(TokenRequest tokenRequest, AuthorizationRequest authRequest);
}