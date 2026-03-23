using Microsoft.Extensions.Caching.Distributed;
using Microsoft.IdentityModel.Tokens;
using Serilog;
using System.Security.Cryptography;

namespace Com.Bayoomed.TelematikFederation;

/// <summary>
///     Startup validation and key bootstrapping.
///     Called once from Program.cs before the application starts accepting requests.
/// </summary>
internal static class StartupValidator
{
    /// <summary>
    ///     A_27585: Validates that all redirect URIs are well-formed absolute HTTPS URIs
    ///     without query, fragment, or user-info components.
    /// </summary>
    internal static void ValidateRedirectUris(string[] redirectUris, bool isDevelopment)
    {
        foreach (var uri in redirectUris)
        {
            if (!Uri.TryCreate(uri, UriKind.Absolute, out var parsed))
                throw new InvalidOperationException($"A_27585: redirect_uri '{uri}' is not a valid absolute URI.");
            if (!isDevelopment && parsed.Scheme != "https")
                throw new InvalidOperationException($"A_27585: redirect_uri '{uri}' must use HTTPS.");
            if (!string.IsNullOrEmpty(parsed.Query))
                throw new InvalidOperationException($"A_27585: redirect_uri '{uri}' must not contain a query part.");
            if (!string.IsNullOrEmpty(parsed.Fragment))
                throw new InvalidOperationException($"A_27585: redirect_uri '{uri}' must not contain a fragment.");
            if (!string.IsNullOrEmpty(parsed.UserInfo))
                throw new InvalidOperationException($"A_27585: redirect_uri '{uri}' must not contain user credentials.");
        }
    }

    /// <summary>
    ///     Validates that OrganizationName is configured (required for federation entity metadata).
    /// </summary>
    internal static void ValidateOrganizationName(string? organizationName)
    {
        if (string.IsNullOrWhiteSpace(organizationName))
            throw new InvalidOperationException("OidcFederation:OrganizationName must be configured.");
    }

    /// <summary>
    ///     A_28208: Resolves or generates UUID v7 key identifiers for all configured private keys.
    ///     Key IDs are persisted in the distributed cache, keyed by JWK thumbprint.
    /// </summary>
    internal static void ResolveAllKeyIds(IDistributedCache cache, OidcFedOptions fedOpts, AuthServerOptions authOpts)
    {
        fedOpts.SignPrivKeyId = ResolveKeyId(cache, fedOpts.SignPrivKey);
        fedOpts.EncPrivKeyId = ResolveKeyId(cache, fedOpts.EncPrivKey);
        if (!string.IsNullOrEmpty(fedOpts.NextSignPrivKey))
            fedOpts.NextSignPrivKeyId = ResolveKeyId(cache, fedOpts.NextSignPrivKey);
        authOpts.SignPrivKeyId = ResolveKeyId(cache, authOpts.SignPrivKey);
    }

    /// <summary>
    ///     A_23185-01: Validates that no key exceeds the maximum age of 398 days.
    /// </summary>
    internal static void ValidateAllKeyAges(OidcFedOptions fedOpts, AuthServerOptions authOpts)
    {
        const int maxKeyAgeDays = 398;
        ValidateKeyAge(fedOpts.SignPrivKeyId, "OidcFederation:SignPrivKey", maxKeyAgeDays);
        ValidateKeyAge(fedOpts.EncPrivKeyId, "OidcFederation:EncPrivKey", maxKeyAgeDays);
        ValidateKeyAge(authOpts.SignPrivKeyId, "AuthServer:SignPrivKey", maxKeyAgeDays);
    }

    private static string ResolveKeyId(IDistributedCache cache, string pemKey)
    {
        using var ecdsa = ECDsa.Create();
        ecdsa.ImportFromPem(pemKey);
        var secKey = new ECDsaSecurityKey(ecdsa);
        var thumbprint = Base64UrlEncoder.Encode(secKey.ComputeJwkThumbprint());
        var cacheKey = $"kid:{thumbprint}";
        var existing = cache.GetString(cacheKey);
        if (existing != null)
            return existing;
        var kid = Guid.CreateVersion7().ToString();
        cache.SetString(cacheKey, kid);
        return kid;
    }

    private static void ValidateKeyAge(string keyId, string keyName, int maxDays)
    {
        if (!Guid.TryParse(keyId, out var guid) || guid.Version != 7) return;
        var createdAt = GetUuid7Timestamp(guid);
        var age = DateTimeOffset.UtcNow - createdAt;
        if (age.TotalDays > maxDays)
            throw new InvalidOperationException(
                $"A_23185-01: {keyName} is {age.TotalDays:F0} days old (created {createdAt:yyyy-MM-dd}). " +
                $"Keys must be rotated after {maxDays} days.");
        if (age.TotalDays > maxDays - 30)
            Log.Warning("A_23185-01: {KeyName} is {AgeDays:F0} days old and approaching the {MaxDays}-day limit. " +
                         "Plan key rotation soon.", keyName, age.TotalDays, maxDays);
    }

    private static DateTimeOffset GetUuid7Timestamp(Guid uuid)
    {
        Span<byte> bytes = stackalloc byte[16];
        uuid.TryWriteBytes(bytes, bigEndian: true, out _);
        long unixMs = ((long)bytes[0] << 40) | ((long)bytes[1] << 32) | ((long)bytes[2] << 24) |
                      ((long)bytes[3] << 16) | ((long)bytes[4] << 8) | bytes[5];
        return DateTimeOffset.FromUnixTimeMilliseconds(unixMs);
    }
}
