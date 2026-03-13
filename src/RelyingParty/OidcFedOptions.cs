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
    ///     OrganizationName (federation_entity.organization_name in entity statement)
    /// </summary>
    public string OrganizationName { get; set; }

    /// <summary>
    ///     ISS of federation master (default ist test environment - TU)
    /// </summary>
    public string FederationMaster { get; set; }

    /// <summary>
    ///     List of scope values (must match the scopes defined in gematik registration form)
    /// </summary>
    public string Scope { get; set; }

    /// <summary>
    ///     Redirect URIs registered with the Federation Master (defaults to {Issuer}/cb)
    /// </summary>
    public string[]? RedirectUris { get; set; }

    /// <summary>
    ///     Default ACR values (defaults to ["gematik-ehealth-loa-high"])
    /// </summary>
    public string[]? DefaultAcrValues { get; set; }

    /// <summary>
    ///     PEM encoded private key used to sign the entity statement
    /// </summary>
    public string SignPrivKey { get; set; }

    /// <summary>
    ///     A_28208: UUID v7 key identifier for the signing key. Auto-generated at startup.
    /// </summary>
    public string SignPrivKeyId { get; set; }

    /// <summary>
    ///     A_24607: PEM encoded next signing private key. When set, its public key is published
    ///     in the JWKS (Entity Statement + signed JWKS) but not yet used for signing.
    ///     This allows depositing the new key at the Federation Master at least 24 h before use.
    /// </summary>
    public string? NextSignPrivKey { get; set; }

    /// <summary>
    ///     A_28208 / A_24607: UUID v7 key identifier for the next signing key. Auto-generated at startup.
    /// </summary>
    public string? NextSignPrivKeyId { get; set; }

    /// <summary>
    ///     PEM encoded private key used to decrypt the token response from sec idp
    /// </summary>
    public string EncPrivKey { get; set; }

    /// <summary>
    ///     A_28208: UUID v7 key identifier for the encryption key. Auto-generated at startup.
    /// </summary>
    public string EncPrivKeyId { get; set; }

    /// <summary>
    ///     A_28209: Previous encryption private keys (PEM encoded) that must remain usable for
    ///     decryption until the exp of the last Entity Statement in which they were published.
    /// </summary>
    public IList<string>? PreviousEncPrivKeys { get; set; }

    /// <summary>
    ///     The Federation Master JWKS exchanged OOB (default is JWKS of fed master in test environment - TU)
    /// </summary>
    public JsonWebKeySet FedMasterJwks { get; set; }
}