using Com.Bayoomed.TelematikFederation;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Options;
using System.Security.Cryptography;

namespace RelyingParty.Test;

[TestClass]
public class StartupValidatorTest
{
    #region ValidateRedirectUris

    [TestMethod]
    public void ValidateRedirectUris_ValidHttpsUri_Passes()
    {
        StartupValidator.ValidateRedirectUris(["https://example.com/cb"], isDevelopment: false);
    }

    [TestMethod]
    public void ValidateRedirectUris_HttpInDevelopment_Passes()
    {
        StartupValidator.ValidateRedirectUris(["http://localhost/cb"], isDevelopment: true);
    }

    [TestMethod]
    public void ValidateRedirectUris_HttpInProduction_Throws()
    {
        var ex = Assert.ThrowsExactly<InvalidOperationException>(
            () => StartupValidator.ValidateRedirectUris(["http://example.com/cb"], isDevelopment: false));
        Assert.IsTrue(ex.Message.Contains("A_27585"));
        Assert.IsTrue(ex.Message.Contains("HTTPS"));
    }

    [TestMethod]
    public void ValidateRedirectUris_MalformedUri_Throws()
    {
        var ex = Assert.ThrowsExactly<InvalidOperationException>(
            () => StartupValidator.ValidateRedirectUris(["not-a-uri"], isDevelopment: false));
        Assert.IsTrue(ex.Message.Contains("A_27585"));
    }

    [TestMethod]
    public void ValidateRedirectUris_UriWithQuery_Throws()
    {
        var ex = Assert.ThrowsExactly<InvalidOperationException>(
            () => StartupValidator.ValidateRedirectUris(["https://example.com/cb?foo=bar"], isDevelopment: false));
        Assert.IsTrue(ex.Message.Contains("query"));
    }

    [TestMethod]
    public void ValidateRedirectUris_UriWithFragment_Throws()
    {
        var ex = Assert.ThrowsExactly<InvalidOperationException>(
            () => StartupValidator.ValidateRedirectUris(["https://example.com/cb#section"], isDevelopment: false));
        Assert.IsTrue(ex.Message.Contains("fragment"));
    }

    [TestMethod]
    public void ValidateRedirectUris_UriWithUserInfo_Throws()
    {
        var ex = Assert.ThrowsExactly<InvalidOperationException>(
            () => StartupValidator.ValidateRedirectUris(["https://user:pass@example.com/cb"], isDevelopment: false));
        Assert.IsTrue(ex.Message.Contains("user credentials"));
    }

    [TestMethod]
    public void ValidateRedirectUris_MultipleUris_ValidatesAll()
    {
        var ex = Assert.ThrowsExactly<InvalidOperationException>(
            () => StartupValidator.ValidateRedirectUris(
                ["https://example.com/cb", "http://example.com/cb2"], isDevelopment: false));
        Assert.IsTrue(ex.Message.Contains("cb2"));
    }

    #endregion

    #region ValidateOrganizationName

    [TestMethod]
    public void ValidateOrganizationName_ValidName_Passes()
    {
        StartupValidator.ValidateOrganizationName("Test Organization");
    }

    [TestMethod]
    public void ValidateOrganizationName_Null_Throws()
    {
        Assert.ThrowsExactly<InvalidOperationException>(
            () => StartupValidator.ValidateOrganizationName(null));
    }

    [TestMethod]
    public void ValidateOrganizationName_Empty_Throws()
    {
        Assert.ThrowsExactly<InvalidOperationException>(
            () => StartupValidator.ValidateOrganizationName(""));
    }

    [TestMethod]
    public void ValidateOrganizationName_Whitespace_Throws()
    {
        Assert.ThrowsExactly<InvalidOperationException>(
            () => StartupValidator.ValidateOrganizationName("   "));
    }

    #endregion

    #region ResolveAllKeyIds

    [TestMethod]
    public void ResolveAllKeyIds_AssignsUuidV7ToAllKeys()
    {
        var cache = CreateMemoryCache();
        var fedOpts = CreateFedOptionsWithKeys();
        var authOpts = CreateAuthOptionsWithKey();

        StartupValidator.ResolveAllKeyIds(cache, fedOpts, authOpts);

        AssertValidUuidV7(fedOpts.SignPrivKeyId);
        AssertValidUuidV7(fedOpts.EncPrivKeyId);
        AssertValidUuidV7(authOpts.SignPrivKeyId);
    }

    [TestMethod]
    public void ResolveAllKeyIds_NextSignPrivKey_ResolvedWhenSet()
    {
        var cache = CreateMemoryCache();
        var fedOpts = CreateFedOptionsWithKeys();
        fedOpts.NextSignPrivKey = GenerateEcPem();
        var authOpts = CreateAuthOptionsWithKey();

        StartupValidator.ResolveAllKeyIds(cache, fedOpts, authOpts);

        AssertValidUuidV7(fedOpts.NextSignPrivKeyId!);
    }

    [TestMethod]
    public void ResolveAllKeyIds_NextSignPrivKey_SkippedWhenNull()
    {
        var cache = CreateMemoryCache();
        var fedOpts = CreateFedOptionsWithKeys();
        fedOpts.NextSignPrivKey = null;
        var authOpts = CreateAuthOptionsWithKey();

        StartupValidator.ResolveAllKeyIds(cache, fedOpts, authOpts);

        Assert.IsNull(fedOpts.NextSignPrivKeyId);
    }

    [TestMethod]
    public void ResolveAllKeyIds_SameKey_ReturnsSameIdFromCache()
    {
        var cache = CreateMemoryCache();
        var fedOpts = CreateFedOptionsWithKeys();
        var authOpts = CreateAuthOptionsWithKey();

        StartupValidator.ResolveAllKeyIds(cache, fedOpts, authOpts);
        var firstSignId = fedOpts.SignPrivKeyId;

        // Reset and resolve again — should return the same cached ID
        fedOpts.SignPrivKeyId = null!;
        StartupValidator.ResolveAllKeyIds(cache, fedOpts, authOpts);

        Assert.AreEqual(firstSignId, fedOpts.SignPrivKeyId);
    }

    #endregion

    #region ValidateAllKeyAges

    [TestMethod]
    public void ValidateAllKeyAges_FreshKeys_Passes()
    {
        var fedOpts = new OidcFedOptions
        {
            SignPrivKeyId = Guid.CreateVersion7().ToString(),
            EncPrivKeyId = Guid.CreateVersion7().ToString()
        };
        var authOpts = new AuthServerOptions
        {
            SignPrivKeyId = Guid.CreateVersion7().ToString()
        };

        StartupValidator.ValidateAllKeyAges(fedOpts, authOpts);
    }

    [TestMethod]
    public void ValidateAllKeyAges_ExpiredKey_Throws()
    {
        var expiredKeyId = Guid.CreateVersion7(DateTimeOffset.UtcNow.AddDays(-400)).ToString();
        var fedOpts = new OidcFedOptions
        {
            SignPrivKeyId = expiredKeyId,
            EncPrivKeyId = Guid.CreateVersion7().ToString()
        };
        var authOpts = new AuthServerOptions
        {
            SignPrivKeyId = Guid.CreateVersion7().ToString()
        };

        var ex = Assert.ThrowsExactly<InvalidOperationException>(
            () => StartupValidator.ValidateAllKeyAges(fedOpts, authOpts));
        Assert.IsTrue(ex.Message.Contains("A_23185-01"));
        Assert.IsTrue(ex.Message.Contains("OidcFederation:SignPrivKey"));
    }

    #endregion

    #region Helpers

    private static IDistributedCache CreateMemoryCache()
    {
        var opts = Options.Create(new MemoryDistributedCacheOptions());
        return new MemoryDistributedCache(opts);
    }

    private static string GenerateEcPem()
    {
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        return ecdsa.ExportECPrivateKeyPem();
    }

    private static OidcFedOptions CreateFedOptionsWithKeys()
    {
        return new OidcFedOptions
        {
            SignPrivKey = GenerateEcPem(),
            EncPrivKey = GenerateEcPem()
        };
    }

    private static AuthServerOptions CreateAuthOptionsWithKey()
    {
        return new AuthServerOptions
        {
            SignPrivKey = GenerateEcPem()
        };
    }

    private static void AssertValidUuidV7(string keyId)
    {
        Assert.IsTrue(Guid.TryParse(keyId, out var guid), $"'{keyId}' is not a valid GUID");
        Assert.AreEqual(7, guid.Version, $"'{keyId}' is not UUID v7");
    }

    #endregion
}
