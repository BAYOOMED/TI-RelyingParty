using System.Text.RegularExpressions;

namespace Com.Bayoomed.TelematikFederation;

/// <summary>
/// Helper to remove empty array properties from a jwks (json) string.
/// </summary>
public static class JwksStringExtension
{
    public static string RemoveEmptyArrayProperties(this string jwks)
        => Regex.Replace(jwks, @"""(x5c|key_ops|oth)"":\s{0,1}\[\],{0,1}", "");
    
}