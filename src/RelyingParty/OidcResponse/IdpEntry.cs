// ReSharper disable InconsistentNaming
#pragma warning disable CS8618 // Non-nullable field must contain a non-null value when exiting constructor. Consider declaring as nullable.
using System.Security.Cryptography;
using System.Text;
using Microsoft.IdentityModel.Tokens;

namespace Com.Bayoomed.TelematikFederation.OidcResponse;

public class IdpEntry
{
    private string _iss;
    public string id { get; set; }
    public string iss
    {
        get => _iss;
        set
        {
            _iss = value;
            id = Base64UrlEncoder.Encode(SHA256.HashData(Encoding.UTF8.GetBytes(value)));
        }
    }
    public string organization_name { get; set; }
    public string logo_uri { get; set; }
    public string user_type_supported { get; set; }
    public bool pkv { get; set; }
}