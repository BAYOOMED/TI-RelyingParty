using Com.Bayoomed.TelematikFederation.OidcRequest;

namespace Com.Bayoomed.TelematikFederation.Services;

/// <summary>
/// Provide calls to the sector idp for auth request and token request using mTLS
/// </summary>
public interface ISectorIdPmTlsService
{
    Task<ParResponse> SendPushedAuthorizationRequest(string iss, string state, string? scope);
    Task<string> SendTokenRequest(TokenRequest request, string tokenEndpoint);
}