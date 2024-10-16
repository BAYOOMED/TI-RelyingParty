using System.IdentityModel.Tokens.Jwt;
using Com.Bayoomed.TelematikFederation.OidcRequest;
using Com.Bayoomed.TelematikFederation.OidcResponse;
using Microsoft.IdentityModel.Tokens;

namespace Com.Bayoomed.TelematikFederation.Services;

/// <summary>
/// provide a typed interface to the cache and set cache lifetime of entries if needed
/// </summary>
public interface ICacheService
{
    Task AddFedMasterEntityStatement(JwtPayload payload);
    Task<JwtPayload?> GetFedMasterEntityStatement();
    Task AddFedMasterEntityStatementForSectorIdP(string iss, JwtPayload payload);
    Task<JwtPayload?> GetFedMasterEntityStatementForSectorIdP(string iss);
    Task<JwtPayload?> GetSectorIdPEntityStatement(string iss);
    Task AddSectorIdPEntityStatement(string iss, JwtPayload payload);
    Task<IList<IdpEntry>?> GetIdpList();
    Task AddIdpList(IList<IdpEntry> idpList, DateTime validTo);
    Task AddSectorIdpJwks(string iss, JsonWebKeySet jwks, DateTime validTo);
    Task<JsonWebKeySet?> GetSectorIdpJwks(string iss);
    Task<string> AddAuthorizationRequest(AuthorizationRequest request, string? linkedCode = null);
    Task<AuthorizationRequest?> GetAndRemoveAuthorizationRequest(string code);
    Task<AuthorizationRequest?> GetAuthorizationRequest(string code);
    Task AddIdToken(string accessToken, JwtPayload idToken);
    Task<JwtPayload?> GetIdToken(string accessToken);
    Task AddParResponse(string state, ParResponse parResponse);
    Task<ParResponse?> GetAndRemoveParResponse(string state);
    Task AddIdTokenFromSectorIdP(string code, JwtPayload idToken);
    Task<JwtPayload?> GetAndRemoveIdTokenFromSectorIdP(string code);
}