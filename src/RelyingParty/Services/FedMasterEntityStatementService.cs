using System.IdentityModel.Tokens.Jwt;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

namespace Com.Bayoomed.TelematikFederation.Services;

public class FedMasterEntityStatementService(HttpClient client, IOptions<OidcFedOptions> options,
    ICacheService cache) : IFedMasterEntityStatementService
{
    private readonly string _federationMaster = options.Value.FederationMaster;
    private readonly JsonWebKeySet _fedMasterJwks = options.Value.FedMasterJwks;

    public async Task<JwtPayload> GetFedMasterEntityStatementAsync()
    {
        var fedEs = await cache.GetFedMasterEntityStatement();
        if (fedEs != null)
            return fedEs;
        var token = await client.GetStringAsync($"{_federationMaster}/.well-known/openid-federation");

        new JwtSecurityTokenHandler().ValidateToken(token, new TokenValidationParameters
        {
            ValidateAudience = false,
            ValidateIssuer = true,
            ValidIssuer = _federationMaster,
            IssuerSigningKeys = _fedMasterJwks.Keys,
            ValidateLifetime = true
        }, out var validatedToken);
        await cache.AddFedMasterEntityStatement((validatedToken as JwtSecurityToken)!.Payload);
        return (validatedToken as JwtSecurityToken)!.Payload;
    }

    public async Task<JsonWebKeySet> GetFedMasterJwks()
    {
        var jwt = await GetFedMasterEntityStatementAsync();
        var jwks = new JsonWebKeySet(jwt["jwks"].ToString());
        return jwks;
    }
}