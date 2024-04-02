using System.IdentityModel.Tokens.Jwt;
using System.Security.Cryptography;
using System.Text;
using Com.Bayoomed.TelematikFederation.OidcRequest;
using Com.Bayoomed.TelematikFederation.OidcResponse;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

namespace Com.Bayoomed.TelematikFederation.Services;

public class TokenRequestValidator(IOptions<AuthServerOptions> options) : ITokenRequestValidator
{
    public (OidcError? error, string? message) ValidateRequest(TokenRequest tokenRequest,
        AuthorizationRequest authRequest)
    {
        if (tokenRequest.grant_type != "authorization_code")
            return (OidcError.unsupported_grant_type, null);
        if (tokenRequest.redirect_uri != authRequest.redirect_uri)
            return (OidcError.invalid_grant, "redirect_uri mismatch");
        if (!string.IsNullOrEmpty(authRequest.code_challenge_method))
        {
            if(tokenRequest.code_verifier == null)
                return (OidcError.invalid_grant, "code_verifier missing");
            var calcChallenge =
                Base64UrlEncoder.Encode(
                    SHA256.Create().ComputeHash(Encoding.ASCII.GetBytes(tokenRequest.code_verifier)));
            if (calcChallenge != authRequest.code_challenge)
                return (OidcError.invalid_grant, "code_verifier mismatch");
        }

        string? clientId;
        if (tokenRequest.client_assertion_type == "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
        {
            if (tokenRequest.client_assertion == null)
                return (OidcError.invalid_client, "client_assertion missing");
            var handler = new JwtSecurityTokenHandler();
            clientId = (handler.ReadToken(tokenRequest.client_assertion) as JwtSecurityToken)?.Subject;
            var client = options.Value.Clients.FirstOrDefault(c => c.ClientId == clientId);
            if (client == null)
                return (OidcError.invalid_client, $"unknown client_id {clientId} in client_assertion");
            try
            {
                _ = handler.ValidateToken(tokenRequest.client_assertion, new TokenValidationParameters
                {
                    ValidateIssuer = true,
                    ValidIssuer = clientId,
                    ValidateAudience = true,
                    ValidAudience = $"{options.Value.Issuer}/auth/Token",
                    ValidateLifetime = true,
                    IssuerSigningKeys = client.ClientAssertionSignKeys,
                    
                }, out var validatedToken);
                var jwt = (validatedToken as JwtSecurityToken)!;
                if (jwt.ValidTo == DateTime.MinValue || jwt.ValidTo - jwt.IssuedAt > TimeSpan.FromMinutes(5))
                    return (OidcError.invalid_client, "client_assertion lifetime too long");
            }
            catch (SecurityTokenValidationException e)
            {
                return (OidcError.invalid_client, $"client_assertion invalid: {e.Message}");
            }
            catch (Exception e)
            {
                return (OidcError.server_error, $"client configuration invalid: {e.Message}");
            }
        }
        else
        {
            clientId = tokenRequest.client_id;
            var client = options.Value.Clients.FirstOrDefault(c => c.ClientId == clientId);
            if (client == null || client.ClientSecret != tokenRequest.client_secret)
                return (OidcError.invalid_client, "client_secret mismatch");
        }

        if (authRequest.client_id != clientId)
            return (OidcError.invalid_client, "client_id mismatch");

        return (null, "");
    }
}