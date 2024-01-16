// ReSharper disable InconsistentNaming

#pragma warning disable CS8618 // Non-nullable field must contain a non-null value when exiting constructor. Consider declaring as nullable.
using Microsoft.IdentityModel.Tokens;

namespace Com.Bayoomed.TelematikFederation;

/// <summary>
///     Configuration values for the Federation Relying Party
/// </summary>
public class OidcFedOptions
{
    /// <summary>
    ///     The issuer of the oidc federation relaying party
    /// </summary>
    public string Issuer { get; set; }

    /// <summary>
    ///     ClientName (part of entity statement)
    /// </summary>
    public string ClientName { get; set; }

    /// <summary>
    ///     ISS of federation master (default ist test environment - TU)
    /// </summary>
    public string FederationMaster { get; set; }

    /// <summary>
    ///     List of scope values (must match the scopes defined in gematik registration form)
    /// </summary>
    public string Scope { get; set; }

    /// <summary>
    ///     PEM encoded private key used to sign the entity statement
    /// </summary>
    public string SignPrivKey { get; set; }

    /// <summary>
    ///     PEM encoded private key used to decrypt the token response from sec idp
    /// </summary>
    public string EncPrivKey { get; set; }

    /// <summary>
    ///     The Federation Master JWKS exchanged OOB (default is JWKS of fed master in test environment - TU)
    /// </summary>
    public JsonWebKeySet FedMasterJwks { get; set; }
}