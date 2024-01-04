// ReSharper disable InconsistentNaming
#pragma warning disable CS8618 // Non-nullable field must contain a non-null value when exiting constructor. Consider declaring as nullable.
using Microsoft.IdentityModel.Tokens;

namespace Com.Bayoomed.TelematikFederation;

/// <summary>
/// Configuration values for the Federation Relying Party
/// </summary>
public class OidcFedOptions
{
    public string Issuer { get; set; }
    public string ClientName { get; set; }
    public string FederationMaster { get; set; }
    public string SignPrivKey { get; set; }
    public string EncPrivKey { get; set; }
    
    /// <summary>
    /// The Federation Master JWKS exchanged OOB
    /// </summary>
    public JsonWebKeySet FedMasterJwks { get; set; }
}