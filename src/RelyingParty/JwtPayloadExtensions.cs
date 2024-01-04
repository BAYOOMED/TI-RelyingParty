using System.IdentityModel.Tokens.Jwt;
using System.Text.Json;

namespace Com.Bayoomed.TelematikFederation;

/// <summary>
/// Extension methods to ease access to common claims in the metadata of the entity statements
/// </summary>
public static class JwtPayloadExtensions
{
    public static string? GetParEndpoint(this JwtPayload payload)
    {
        return (payload["metadata"] as JsonElement? ?? default)
            .GetProperty("openid_provider").GetProperty("pushed_authorization_request_endpoint").GetString();;
    }
    
    public static string? GetAuthorizationEndpoint(this JwtPayload payload)
    {
        return (payload["metadata"] as JsonElement? ?? default)
            .GetProperty("openid_provider").GetProperty("authorization_endpoint").GetString();;
    }
    
    public static string? GetIdpListEndpoint(this JwtPayload payload)
    {
        return (payload["metadata"] as JsonElement? ?? default)
            .GetProperty("federation_entity").GetProperty("idp_list_endpoint").GetString();;
    }
    
    public static string? GetFederationFetchEndpoint(this JwtPayload payload)
    {
        return (payload["metadata"] as JsonElement? ?? default)
            .GetProperty("federation_entity").GetProperty("federation_fetch_endpoint").GetString();;
    }
    
    public static string? GetTokenEndpoint(this JwtPayload payload)
    {
        return (payload["metadata"] as JsonElement? ?? default)
            .GetProperty("openid_provider").GetProperty("token_endpoint").GetString();;
    }
    
    public static string? GetSignedJwksUri(this JwtPayload payload)
    {
        return (payload["metadata"] as JsonElement? ?? default)
            .GetProperty("openid_provider").GetProperty("signed_jwks_uri").GetString();;
    }
}