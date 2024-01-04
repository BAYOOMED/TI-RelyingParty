// ReSharper disable InconsistentNaming

using Microsoft.IdentityModel.Tokens;

#pragma warning disable CS8618 // Non-nullable field must contain a non-null value when exiting constructor. Consider declaring as nullable.
namespace Com.Bayoomed.TelematikFederation;

/// <summary>
/// Configuration options for the AuthServer
/// </summary>
public class AuthServerOptions
{
    public string Issuer { get; set; }
    public string SignPrivKey { get; set; }
    public IList<OidcClient> Clients { get; set; }
}

/// <summary>
/// The server can have multiple clients. Each client is configures using those values
/// </summary>
public class OidcClient
{
    public string ClientId { get; set; }
    public string ClientSecret { get; set; }
    public IList<JsonWebKey> ClientAssertionSignKeys { get; set; }
    public IList<string> RedirectUris { get; set; }
    public string LoginPagePath { get; set; } = "default/login.html";
}