using Com.Bayoomed.TelematikFederation.OidcResponse;

namespace Com.Bayoomed.TelematikFederation.Services;

/// <summary>
/// Interface for the service that provides the list of sector idps
/// </summary>
public interface IFedMasterIdpListService
{
    /// <summary>
    /// Get the list of sector IdPs
    /// </summary>
    /// <returns>List of sector IdPs</returns>
    Task<IList<IdpEntry>> GetIdpListAsync();
}