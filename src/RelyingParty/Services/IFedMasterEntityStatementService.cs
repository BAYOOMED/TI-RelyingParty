using System.IdentityModel.Tokens.Jwt;
using Microsoft.IdentityModel.Tokens;

namespace Com.Bayoomed.TelematikFederation.Services;

/// <summary>
/// Provide the FedMasterEntityStatement and the FedMasterJwks
/// </summary>
public interface IFedMasterEntityStatementService
{
    Task<JwtPayload> GetFedMasterEntityStatementAsync();
    Task<JsonWebKeySet> GetFedMasterJwks();

}