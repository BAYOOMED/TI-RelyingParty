using System.Reflection;
using OpenTelemetry.Metrics;
using OpenTelemetry.Resources;
using OpenTelemetry.Trace;
using Serilog;
using Serilog.Sinks.OpenTelemetry;

namespace Com.Bayoomed.TelematikFederation;

public static class OtelSetupExtension
{
    private static string AppVersion => Assembly.GetEntryAssembly()!
        .GetCustomAttribute<AssemblyInformationalVersionAttribute>()!
        .InformationalVersion;

    public static IServiceCollection AddOtelTracingAndMetrics(this IServiceCollection services, string serviceName, string hostName,
        string environment, string otelEndpoint)
    {
        services.AddOpenTelemetry()
            .ConfigureResource(resource => resource
                .AddService(serviceName, serviceVersion: AppVersion)
                .AddAttributes(new KeyValuePair<string, object>[]
                {
                    new("deployment.environment", environment),
                    new("host.name", hostName)
                }))
            .WithTracing(tracing => tracing
                .AddAspNetCoreInstrumentation()
                .AddRedisInstrumentation()
                .AddHttpClientInstrumentation(opt =>
                    opt.FilterHttpRequestMessage =
                        message => message.RequestUri?.Host != new Uri(otelEndpoint).Host)
                .AddOtlpExporter(o=> o.Endpoint = new Uri(otelEndpoint)))
            .WithMetrics(b => b
                .AddRuntimeInstrumentation()
                .AddHttpClientInstrumentation()
                .AddAspNetCoreInstrumentation()
                .AddOtlpExporter(o=> o.Endpoint = new Uri(otelEndpoint)));
        return services;
    }

    public static LoggerConfiguration AddOtel(this LoggerConfiguration conf, string serviceName, string hostName,
        string environment, string otelEndpoint)
    {
        conf.WriteTo.OpenTelemetry(options =>
        {
            options.Endpoint = otelEndpoint;
            options.Protocol = OtlpProtocol.Grpc;
            options.ResourceAttributes = new Dictionary<string, object>
            {
                ["service.name"] = serviceName,
                ["service.version"] = AppVersion,
                ["deployment.environment"] = environment,
                ["host.name"] = hostName
            };
        });
        return conf;
    }
}