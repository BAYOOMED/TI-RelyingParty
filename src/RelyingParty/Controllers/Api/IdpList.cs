using System.IdentityModel.Tokens.Jwt;
using Com.Bayoomed.TelematikFederation.OidcResponse;
using Com.Bayoomed.TelematikFederation.Services;
using Microsoft.AspNetCore.Cors;
using Microsoft.AspNetCore.Mvc;

namespace Com.Bayoomed.TelematikFederation.Controllers.Api;

[ApiController]
public class IdpList(IFedMasterIdpListService idpService) : Controller
{
    /// <summary>
    /// Returns a list of available IdPs
    /// </summary>
    /// <returns></returns>
    [HttpGet]
    [Route("/idp")]
    [EnableCors("idplist")]
    public async Task<IList<IdpEntry>> GetAll()
    {
        return await idpService.GetIdpListAsync();
    }
}