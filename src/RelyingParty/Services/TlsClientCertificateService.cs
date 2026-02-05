using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.IdentityModel.Tokens;

namespace Com.Bayoomed.TelematikFederation.Services;

public class TlsClientCertificateService : ITlsClientCertificateService
{
    private readonly IDistributedCache _cache;

    public TlsClientCertificateService(IDistributedCache cache)
    {
        _cache = cache;
        if(_cache.GetString("clientCertPem") == null || _cache.GetString("clientCertKeyPem") == null)
            CreateClientCertificate();
    }
    
    public X509Certificate2 GetClientCertificate()
    {
        var cert = LoadFromCache();
        if (cert == null || cert.NotAfter < DateTimeOffset.UtcNow.AddDays(10))
            return CreateClientCertificate();
        return cert;
    }

    public string GetCertPem()
    {
        return _cache.GetString("clientCertPem")!;
    }

    private X509Certificate2? LoadFromCache()
    {
        var certPem = _cache.GetString("clientCertPem");
        var keyPem = _cache.GetString("clientCertKeyPem");
        if (certPem != null && keyPem != null)
        {
            var cert = X509Certificate2.CreateFromPem(certPem);
            var key = ECDsa.Create();
            key.ImportFromEncryptedPem(keyPem, "111");
            var certWithKey = cert.CopyWithPrivateKey(key);
            return certWithKey;
        }
        return null;
    }

    private X509Certificate2 CreateClientCertificate()
    {
        var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256); // generate asymmetric key pair
        var req = new CertificateRequest("cn=TlsClientCert", ecdsa, HashAlgorithmName.SHA256);
        var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddDays(350));
        var certPem = cert.ExportCertificatePem();
        var keyPem = ecdsa.ExportEncryptedPkcs8PrivateKeyPem(Encoding.ASCII.GetBytes("111"),
            new PbeParameters(PbeEncryptionAlgorithm.Aes256Cbc, HashAlgorithmName.SHA256, 10));
        _cache.SetString("clientCertPem", certPem);
        _cache.SetString("clientCertKeyPem", keyPem);
        return cert;
    }
}