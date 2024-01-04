// ReSharper disable InconsistentNaming
#pragma warning disable CS8618 // Non-nullable field must contain a non-null value when exiting constructor. Consider declaring as nullable.
namespace Com.Bayoomed.TelematikFederation.OidcRequest;

public class AuthorizationRequest
{
    public string response_type { get; set; }
    public string client_id { get; set; }
    public string redirect_uri { get; set; }
    public string scope { get; set; }
    public string state { get; set; }
    public string nonce { get; set; }
    public string code_challenge { get; set; }
    public string code_challenge_method { get; set; }
    public string? acr_values { get; set; }
    public string? login_hint { get; set; }
}