// ReSharper disable InconsistentNaming
#pragma warning disable CS8618 // Non-nullable field must contain a non-null value when exiting constructor. Consider declaring as nullable.
namespace Com.Bayoomed.TelematikFederation.OidcRequest;

public class TokenResponse
{
    public string id_token { get; set; }
    public string access_token { get; set; }
    public string token_type { get; set; }
}