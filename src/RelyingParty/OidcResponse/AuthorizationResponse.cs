// ReSharper disable InconsistentNaming
#pragma warning disable CS8618 // Non-nullable field must contain a non-null value when exiting constructor. Consider declaring as nullable.
namespace Com.Bayoomed.TelematikFederation.OidcResponse;

public class AuthorizationResponse
{
    public string request_uri { get; set; }
    public long expires_in { get; set; }
}