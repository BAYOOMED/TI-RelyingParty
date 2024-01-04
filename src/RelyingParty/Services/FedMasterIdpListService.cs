using System.IdentityModel.Tokens.Jwt;
using System.Text.Json;
using Com.Bayoomed.TelematikFederation.OidcResponse;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.IdentityModel.Tokens;

namespace Com.Bayoomed.TelematikFederation.Services;

public class FedMasterIdpListService(IFedMasterEntityStatementService fmesService, HttpClient client,
    ICacheService cache) : IFedMasterIdpListService
{
    public async Task<IList<IdpEntry>> GetIdpListAsync()
    {
        var idpList = await cache.GetIdpList();
        if (idpList != null)
            return idpList;
        var fmes = await fmesService.GetFedMasterEntityStatementAsync();
        var token = await client.GetStringAsync(fmes.GetIdpListEndpoint());
        var jwks = await fmesService.GetFedMasterJwks();

        var handler = new JwtSecurityTokenHandler();
        handler.ValidateToken(token, new TokenValidationParameters
        {
            ValidateAudience = false,
            ValidateIssuer = true,
            ValidIssuer = fmes.Iss,
            ValidateIssuerSigningKey = true,
            IssuerSigningKeys = jwks.Keys,
            ValidateLifetime = true
        }, out var validatedToken);
        idpList = JsonSerializer.Deserialize<List<IdpEntry>>(
            ((validatedToken as JwtSecurityToken)!).Payload["idp_entity"].ToString()!);
        await cache.AddIdpList(idpList!, fmes.ValidTo);
        return idpList!;
    }
}