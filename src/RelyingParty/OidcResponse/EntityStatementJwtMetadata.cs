using System.Text.Json.Serialization;
using Microsoft.IdentityModel.Tokens;

namespace Com.Bayoomed.TelematikFederation.OidcResponse;

public class EntityStatementJwtMetadata(string issuer, string clientName)
{
    [JsonPropertyName("openid_relying_party")]
    public OpenIdRelyingParty OpenIdRelyingParty { get; } = new(issuer, clientName);

    [JsonPropertyName("federation_entity")]
    public FederationEntity FederationEntity { get; } = new(clientName);
}

public class OpenIdRelyingParty(string issuer, string clientName)
{
    [JsonPropertyName("client_name")] public string ClientName => clientName;

    [JsonPropertyName("signed_jwks_uri")] public string SignedJwksUri => $"{issuer}/jwks.jwt";

    [JsonPropertyName("redirect_uris")] public string[] RedirectUris => [$"{issuer}/cb"];

    [JsonPropertyName("grant_types")] public string[] GrantTypes => ["authorization_code"];

    [JsonPropertyName("response_types")] public string[] ResponseTypes => ["code"];

    [JsonPropertyName("client_registration_types")]
    public string[] ClientRegistrationTypes => new[] { "automatic" };

    [JsonPropertyName("require_pushed_authorization_requests")]
    public bool RequirePushedAuthorizationRequests => true;

    [JsonPropertyName("token_endpoint_auth_method")]
    public string TokenEndpointAuthMethod => "self_signed_tls_client_auth";

    [JsonPropertyName("default_acr_values")]
    public string DefaultAcrValues => "gematik-ehealth-loa-high";

    [JsonPropertyName("id_token_signed_response_alg")]
    public string IdTokenSignedResponseAlg => "ES256";

    [JsonPropertyName("id_token_encrypted_response_alg")]
    public string IdTokenEncryptedResponseAlg => "ECDH-ES";

    [JsonPropertyName("id_token_encrypted_response_enc")]
    public string IdTokenEncryptedResponseEnc => "A256GCM";

    [JsonPropertyName("scope")] public string Scope => "openid urn:telematik:versicherter";
}

public class FederationEntity(string clientName)
{
    [JsonPropertyName("name")] public string Name => clientName;
}