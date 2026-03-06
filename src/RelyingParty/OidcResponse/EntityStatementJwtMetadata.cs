using System.Text.Json.Serialization;

namespace Com.Bayoomed.TelematikFederation.OidcResponse;

public class EntityStatementJwtMetadata(
    string issuer,
    string clientName,
    string scope,
    string organizationName,
    string[]? redirectUris = null,
    string[]? defaultAcrValues = null)
{
    [JsonPropertyName("openid_relying_party")]
    public OpenIdRelyingParty OpenIdRelyingParty { get; } = new(issuer, clientName, scope, redirectUris, defaultAcrValues);

    [JsonPropertyName("federation_entity")]
    public FederationEntity FederationEntity { get; } = new(clientName, organizationName);
}

public class OpenIdRelyingParty(
    string issuer,
    string clientName,
    string scope,
    string[]? redirectUris = null,
    string[]? defaultAcrValues = null)
{
    [JsonPropertyName("client_name")] public string ClientName => clientName;

    [JsonPropertyName("signed_jwks_uri")] public string SignedJwksUri => $"{issuer}/jwks.jwt";

    [JsonPropertyName("redirect_uris")] public string[] RedirectUris => redirectUris ?? [$"{issuer}/cb"];

    [JsonPropertyName("grant_types")] public string[] GrantTypes => ["authorization_code"];

    [JsonPropertyName("response_types")] public string[] ResponseTypes => ["code"];

    [JsonPropertyName("client_registration_types")]
    public string[] ClientRegistrationTypes => new[] { "automatic" };

    [JsonPropertyName("require_pushed_authorization_requests")]
    public bool RequirePushedAuthorizationRequests => true;

    [JsonPropertyName("token_endpoint_auth_method")]
    public string TokenEndpointAuthMethod => "self_signed_tls_client_auth";

    [JsonPropertyName("default_acr_values")]
    public string[] DefaultAcrValues => defaultAcrValues ?? ["gematik-ehealth-loa-high"];

    [JsonPropertyName("id_token_signed_response_alg")]
    public string IdTokenSignedResponseAlg => "ES256";

    [JsonPropertyName("id_token_encrypted_response_alg")]
    public string IdTokenEncryptedResponseAlg => "ECDH-ES";

    [JsonPropertyName("id_token_encrypted_response_enc")]
    public string IdTokenEncryptedResponseEnc => "A256GCM";

    [JsonPropertyName("scope")] public string Scope => scope;

    [JsonPropertyName("ti_features_supported")]
    public TiFeaturesSupported TiFeaturesSupported { get; } = new();
}

public class TiFeaturesSupported
{
    [JsonPropertyName("id_token_version_supported")]
    public string[] IdTokenVersionSupported => ["1.0.0", "2.0.0"];
}

public class FederationEntity(string clientName, string organizationName)
{
    [JsonPropertyName("name")] public string Name => clientName;

    [JsonPropertyName("organization_name")]
    public string OrganizationName => organizationName;
}