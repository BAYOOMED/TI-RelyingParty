using System.Security.Cryptography.X509Certificates;

namespace Com.Bayoomed.TelematikFederation.Services;

/// <summary>
/// provide certificate for mTLS authentication (self signed and automatically (re)generated)
/// </summary>
public interface ITlsClientCertificateService
{
    X509Certificate2 GetClientCertificate();
    string GetCertPem();
}