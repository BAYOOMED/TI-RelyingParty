using System.Text.Json.Serialization;

namespace Com.Bayoomed.TelematikFederation.OidcResponse;

public class EntityStatementJwtMetadata(
    string issuer,
    string clientName,
    string scope,
    string organizationName,
    string[]? redirectUris = null,
    string[]? defaultAcrValues = null,
    string[]? keywords = null,
    string[]? contacts = null)
{
    [JsonPropertyName("openid_relying_party")]
    public OpenIdRelyingParty OpenIdRelyingParty { get; } =
        new(issuer, clientName, scope, organizationName, redirectUris, defaultAcrValues, keywords, contacts);

    [JsonPropertyName("federation_entity")]
    public FederationEntity FederationEntity { get; } = new(clientName);
}

public class OpenIdRelyingParty(
    string issuer,
    string clientName,
    string scope,
    string organizationName,
    string[]? redirectUris = null,
    string[]? defaultAcrValues = null,
    string[]? keywords = null,
    string[]? contacts = null)
{
    [JsonPropertyName("client_name")] public string ClientName => clientName;

    // gemSpec_IDP_FD A_23034-02: organization_name belongs to the openid_relying_party metadata block
    [JsonPropertyName("organization_name")]
    public string OrganizationName => organizationName;

    // gemSpec_IDP_FD A_23034-02: product_type / product_type_version (empty arrays are removed from the ES)
    [JsonPropertyName("keywords")] public string[] Keywords => keywords ?? [];

    // gemSpec_IDP_FD A_23034-02: support e-mail address (empty arrays are removed from the ES)
    [JsonPropertyName("contacts")] public string[] Contacts => contacts ?? [];

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

public class FederationEntity(string clientName)
{
    [JsonPropertyName("name")] public string Name => clientName;
}