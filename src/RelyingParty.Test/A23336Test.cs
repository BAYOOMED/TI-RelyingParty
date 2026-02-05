using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Com.Bayoomed.TelematikFederation.Services;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Options;

namespace RelyingParty.Test;

[TestClass]
public class A23336Test
{
    /// <summary>
    ///     A_23336 - Mindestvorgaben für Schlüssel von Fachdiensten als Teilnehmer der TI-Föderation
    ///     Ein Fachdienst als Teilnehmer der TI-Föderation MUSS bei dem eingesetzten Schlüsselmaterial (Signatur,
    ///     Autorisierungstoken, Entity Statement, etc.), folgende Vorgaben umsetzen:
    ///     1. Alle verwendeten Schlüssel MÜSSEN ein Sicherheitsniveau von 120 Bit ermöglichen (vgl. [gemSpec_Krypt#5
    ///     "Migration 120-Bit Sicherheitsniveau"]).
    ///     2. Alle ECC-Schlüssel MÜSSEN auf einem folgenden der Domainparameter (Kurven) basieren:
    ///     a. P-256 oder P-384 [FIPS-186-4]
    /// </summary>
    [TestMethod]
    public void A23336_CheckCurveGeneratedTlsKey()
    {
        var cache = new MemoryDistributedCache(
            new OptionsWrapper<MemoryDistributedCacheOptions>(new MemoryDistributedCacheOptions()));
        var tlsCertService = new TlsClientCertificateService(cache);
        var cert = tlsCertService.GetClientCertificate();
        var pubKey = cert.GetECDsaPublicKey();
        
        Assert.IsNotNull(pubKey);
        
        var para = pubKey.ExportParameters(false);
        
        Assert.IsTrue(para.Curve.Oid.Value == ECCurve.NamedCurves.nistP256.Oid.Value ||
                      para.Curve.Oid.Value == ECCurve.NamedCurves.nistP384.Oid.Value);
    }
}