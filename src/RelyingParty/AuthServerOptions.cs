// ReSharper disable InconsistentNaming

using Microsoft.IdentityModel.Tokens;

#pragma warning disable CS8618 // Non-nullable field must contain a non-null value when exiting constructor. Consider declaring as nullable.
namespace Com.Bayoomed.TelematikFederation;

/// <summary>
///     Configuration options for the AuthServer
/// </summary>
public class AuthServerOptions
{
    /// <summary>
    /// ISS of the AuthServer
    /// </summary>
    public string Issuer { get; set; }
    
    /// <summary>
    /// PEM encoded private key used to sign the issued tokens
    /// </summary>
    public string SignPrivKey { get; set; }
    
    /// <summary>
    /// List of configured clients
    /// </summary>
    public IList<OidcClient> Clients { get; set; }
}

/// <summary>
///     The server can have multiple clients. Each client is configures using those values
/// </summary>
public class OidcClient
{
    /// <summary>
    ///     The client id
    /// </summary>
    public string ClientId { get; set; }

    /// <summary>
    ///     The client secret if using client_secret_post authentication method
    /// </summary>
    public string ClientSecret { get; set; }

    /// <summary>
    ///     The JWKS key(s) used to sign the client assertion if using private_key_jwt authentication method
    /// </summary>
    public IList<JsonWebKey> ClientAssertionSignKeys { get; set; }

    /// <summary>
    ///     List of allowed redirect uris. No Wildcards allowed
    /// </summary>
    public IList<string> RedirectUris { get; set; }

    /// <summary>
    ///     path to custom login page
    /// </summary>
    public string LoginPagePath { get; set; } = "default/login.html";

    /// <summary>
    ///     Scopes to request from sector idp. Default is all defined scopes
    /// </summary>
    public string SecIdpRequestedScope { get; set; }
}