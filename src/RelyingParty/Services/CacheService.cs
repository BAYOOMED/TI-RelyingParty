using System.IdentityModel.Tokens.Jwt;
using System.Security.Cryptography;
using Com.Bayoomed.TelematikFederation.OidcRequest;
using Com.Bayoomed.TelematikFederation.OidcResponse;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.IdentityModel.Tokens;

namespace Com.Bayoomed.TelematikFederation.Services;

public class CacheService(IDistributedCache cache) : ICacheService
{
    public Task AddFedMasterEntityStatement(JwtPayload payload)
    {
        var exp = payload.ValidTo > DateTime.UtcNow.AddHours(12) ? DateTime.UtcNow.AddHours(12) : payload.ValidTo;
        return cache.SetAsync("fedEs", payload, exp);
    }

    public Task<JwtPayload?> GetFedMasterEntityStatement()
    {
        return cache.GetJwtPayloadAsync("fedEs");
    }

    public Task AddFedMasterEntityStatementForSectorIdP(string iss, JwtPayload payload)
    {
        var exp = payload.ValidTo > DateTime.UtcNow.AddHours(12) ? DateTime.UtcNow.AddHours(12) : payload.ValidTo;
        return cache.SetAsync($"fedEsSec_{iss}", payload, exp);
    }

    public Task<JwtPayload?> GetFedMasterEntityStatementForSectorIdP(string iss)
    {
        return cache.GetJwtPayloadAsync($"fedEsSec_{iss}");
    }

    public Task<JwtPayload?> GetSectorIdPEntityStatement(string iss)
    {
        return cache.GetJwtPayloadAsync($"secEs_{iss}");
    }

    public Task AddSectorIdPEntityStatement(string iss, JwtPayload payload)
    {
        var exp = payload.ValidTo > DateTime.UtcNow.AddHours(12) ? DateTime.UtcNow.AddHours(12) : payload.ValidTo;
        return cache.SetAsync($"secEs_{iss}", payload, exp);
    }

    public Task<IList<IdpEntry>?> GetIdpList()
    {
        return cache.GetAsync<IList<IdpEntry>>("idplist");
    }

    public Task AddIdpList(IList<IdpEntry> idpList, DateTime validTo)
    {
        return cache.SetAsync("idplist", idpList, validTo);
    }

    public Task AddSectorIdpJwks(string iss, JsonWebKeySet jwks, DateTime validTo)
    {
        return cache.SetAsync($"secjwks_{iss}", jwks, validTo);
    }

    public async Task<JsonWebKeySet?> GetSectorIdpJwks(string iss)
    {
        var json = await cache.GetStringAsync($"secjwks_{iss}");
        return json == null ? null : new JsonWebKeySet(json);
    }

    public Task<string> AddAuthorizationRequest(AuthorizationRequest request, string? linkedCode = null)
    {
        var code = Base64UrlEncoder.Encode(RandomNumberGenerator.GetBytes(32));
        return cache.SetAsync($"login_{code}", new LinkedAuthRequest(request, linkedCode),
            TimeSpan.FromMinutes(15)).ContinueWith(_ => code);
    }

    public async Task<AuthorizationRequest?> GetAndRemoveAuthorizationRequest(string code)
    {
        var req = await cache.GetAndRemoveAsync<LinkedAuthRequest>($"login_{code}");
        if (req?.LinkedCode != null)
            await GetAndRemoveAuthorizationRequest(req.LinkedCode);
        return req?.Request;
    }

    public async Task<AuthorizationRequest?> GetAuthorizationRequest(string code)
    {
        var req = await cache.GetAsync<LinkedAuthRequest>($"login_{code}");
        return req?.Request;
    }

    public Task AddIdToken(string accessToken, JwtPayload idToken)
    {
        return cache.SetAsync($"acc_{accessToken}", idToken, TimeSpan.FromMinutes(10));
    }

    public Task<JwtPayload?> GetIdToken(string accessToken)
    {
        return cache.GetJwtPayloadAsync($"acc_{accessToken}");
    }

    public Task AddParResponse(string state, ParResponse parResponse)
    {
        return cache.SetAsync($"par_{state}", parResponse, TimeSpan.FromMinutes(15));
    }

    public Task<ParResponse?> GetAndRemoveParResponse(string state)
    {
        return cache.GetAndRemoveAsync<ParResponse>($"par_{state}");
    }

    public Task AddIdTokenFromSectorIdP(string code, JwtPayload idToken)
    {
        return cache.SetAsync($"secIdToken_{code}", idToken, TimeSpan.FromMinutes(15));
    }

    public Task<JwtPayload?> GetAndRemoveIdTokenFromSectorIdP(string code)
    {
        return cache.GetAndRemoveJwtPayloadAsync($"secIdToken_{code}");
    }

    private record LinkedAuthRequest(AuthorizationRequest Request, string? LinkedCode)
    {
        // public required AuthorizationRequest Request { get; set; } = Request;
        // public required string? LinkedCode { get; set; } = LinkedCode;
    }
}