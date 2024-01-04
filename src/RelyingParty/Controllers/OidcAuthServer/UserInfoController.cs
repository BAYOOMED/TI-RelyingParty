using System.IdentityModel.Tokens.Jwt;
using Com.Bayoomed.TelematikFederation.Services;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Caching.Memory;

namespace Com.Bayoomed.TelematikFederation.Controllers.OidcAuthServer;

public class UserInfoController(ICacheService cache) : Controller
{
    /// <summary>
    /// We have this because its required by the spec.
    /// Returns only the sub claim.
    /// </summary>
    /// <param name="authorization"></param>
    /// <returns></returns>
    [HttpGet]
    public async Task<IActionResult> Get([FromHeader] string authorization)
    {
        authorization = authorization.Replace("Bearer ", "");
        var idToken = await cache.GetIdToken(authorization);
        if (idToken == null)
            return Unauthorized();
        
        return Json(new
        {
            sub = idToken.Claims.First(c=>c.Type == JwtRegisteredClaimNames.Sub).Value
        });
    }
}