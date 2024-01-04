using System.IdentityModel.Tokens.Jwt;
using System.Text.Json;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

namespace Com.Bayoomed.TelematikFederation.Services;

public class SectorIdPEntityStatementService(HttpClient client, IOptions<OidcFedOptions> options,
    ICacheService cache, IFedMasterEntityStatementService fmesService) : ISectorIdPEntityStatementService
{
    private readonly string _federationMaster = options.Value.FederationMaster;

    public async Task<JwtPayload> GetSectorIdPEntityStatement(string iss, bool forceRefresh = false)
    {
        var sectorEs = forceRefresh == false ? await cache.GetSectorIdPEntityStatement(iss) : null;
        if (sectorEs != null)
            return sectorEs;

        var token = await client.GetStringAsync($"{iss}/.well-known/openid-federation");
        new JwtSecurityTokenHandler().ValidateToken(token, new TokenValidationParameters
        {
            ValidateAudience = false,
            ValidateIssuer = true,
            ValidIssuer = iss,
            IssuerSigningKeys = (await GetJwksForSectorIdpFromFedMaster(iss)).Keys,
            ValidateLifetime = true
        }, out var validatedToken);
        await cache.AddSectorIdPEntityStatement(iss, (validatedToken as JwtSecurityToken)!.Payload);
        return (validatedToken as JwtSecurityToken)!.Payload;
    }

    public async Task<JsonWebKeySet> GetSectorIdPJwks(string iss, bool forceRefresh = false)
    {
        var jwks = forceRefresh == false ? await cache.GetSectorIdpJwks(iss) : null;
        if (jwks != null) return jwks;
        var secEs = await GetSectorIdPEntityStatement(iss, forceRefresh);
        jwks = new JsonWebKeySet(secEs["jwks"].ToString());
        var signedJwksUrl = secEs.GetSignedJwksUri();
        if (signedJwksUrl == null) return jwks;

        var token = await client.GetStringAsync(signedJwksUrl);
        new JwtSecurityTokenHandler().ValidateToken(token, new TokenValidationParameters
        {
            ValidateAudience = false,
            ValidateIssuer = false,
            IssuerSigningKeys = jwks.Keys,
            ValidateLifetime = false
        }, out var validatedToken);
        var jwksFromUrl =
            JsonSerializer.Deserialize<List<JsonWebKey>>((validatedToken as JwtSecurityToken)!.Payload["keys"]
                .ToString()!)!;

        foreach (var key in jwksFromUrl.Where(k2 => jwks.Keys.All(k => k.KeyId != k2.KeyId))) jwks.Keys.Add(key);
        await cache.AddSectorIdpJwks(iss, jwks, secEs.ValidTo);
        return jwks;
    }

    private async Task<JwtPayload> GetFedMasterEsForSectorIdP(string iss)
    {
        var fedEs = await cache.GetFedMasterEntityStatementForSectorIdP(iss);
        if (fedEs != null)
            return fedEs;
        var fmes = await fmesService.GetFedMasterEntityStatementAsync();
        var fetchgUrl = fmes.GetFederationFetchEndpoint();
        var token = await client.GetStringAsync($"{fetchgUrl}?iss={_federationMaster}&sub={iss}");
        new JwtSecurityTokenHandler().ValidateToken(token, new TokenValidationParameters
        {
            ValidateAudience = false,
            ValidateIssuer = false,
            IssuerSigningKeys = (await fmesService.GetFedMasterJwks()).Keys,
            ValidateLifetime = true
        }, out var validatedToken);
        await cache.AddFedMasterEntityStatementForSectorIdP(iss, (validatedToken as JwtSecurityToken)!.Payload);
        return (validatedToken as JwtSecurityToken)!.Payload;
    }

    private async Task<JsonWebKeySet> GetJwksForSectorIdpFromFedMaster(string iss)
    {
        var esMasterSec = await GetFedMasterEsForSectorIdP(iss);
        var jwks = new JsonWebKeySet(esMasterSec["jwks"].ToString());
        return jwks;
    }
}