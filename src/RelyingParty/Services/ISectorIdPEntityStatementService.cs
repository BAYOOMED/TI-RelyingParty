using System.IdentityModel.Tokens.Jwt;
using Microsoft.IdentityModel.Tokens;

namespace Com.Bayoomed.TelematikFederation.Services;

/// <summary>
/// Provide the SectorIdPEntityStatement and the SectorIdPJwks for a given iss
/// </summary>
public interface ISectorIdPEntityStatementService
{
    Task<JwtPayload> GetSectorIdPEntityStatement(string iss, bool forceRefresh = false);
    Task<JsonWebKeySet> GetSectorIdPJwks(string iss, bool forceRefresh = false);
}