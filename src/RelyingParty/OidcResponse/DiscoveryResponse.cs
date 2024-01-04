// ReSharper disable InconsistentNaming
#pragma warning disable CS8618 // Non-nullable field must contain a non-null value when exiting constructor. Consider declaring as nullable.

namespace Com.Bayoomed.TelematikFederation.OidcResponse;

public class DiscoveryResponse
{
    public string issuer { get; set; }
    public string authorization_endpoint { get; set; }
    public string token_endpoint { get; set; }
    public string userinfo_endpoint { get; set; }
    public IList<string> token_endpoint_auth_methods_supported { get; set; }
    public string jwks_uri { get; set; }
    public IList<string> scopes_supported { get; set; }
    public IList<string> response_types_supported { get; set; }
    public IList<string> subject_types_supported { get; set; }
    public IList<string> id_token_signing_alg_values_supported { get; set; }
    public IList<string> claims_supported { get; set; }
    public bool claims_parameter_supported { get; set; }
    public IList<string> code_challenge_methods_supported { get; set; }
}
