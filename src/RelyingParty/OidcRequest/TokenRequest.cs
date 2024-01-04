// ReSharper disable InconsistentNaming
#pragma warning disable CS8618 // Non-nullable field must contain a non-null value when exiting constructor. Consider declaring as nullable.
namespace Com.Bayoomed.TelematikFederation.OidcRequest;

public class TokenRequest
{
    public string? client_id { get; set; }
    public string? client_secret { get; set; }
    public string code { get; set; }
    public string grant_type { get; set; }
    public string redirect_uri { get; set; }
    public string code_verifier { get; set; }
    public string? client_assertion_type { get; set; }
    public string? client_assertion { get; set; }
}