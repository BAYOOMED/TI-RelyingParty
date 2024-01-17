namespace Com.Bayoomed.TelematikFederation;

public class CommonOptions
{
    /// <summary>
    ///     The Redis host to use for caching. Mandatory for production environment
    /// </summary>
    public string? RedisHost { get; set; }

    /// <summary>
    ///     OpenTelemetry exporter endpoint. If set, metrics, logs and traces will be exported to this endpoint
    /// </summary>
    public string? OtelExporterOtlpEndpoint { get; set; }

    /// <summary>
    ///     Value of the XAUTH header needed to access the Gematik sec IdP in TU
    /// </summary>
    public string? GematikXAuthHeader { get; set; }
}