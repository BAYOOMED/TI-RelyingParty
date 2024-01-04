using Com.Bayoomed.TelematikFederation;
using Com.Bayoomed.TelematikFederation.Services;
using Microsoft.Extensions.Hosting.Internal;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Serilog;
using StackExchange.Redis;

var builder = WebApplication.CreateBuilder(args);
var commonOptions = builder.Configuration.Get<CommonOptions>()!;
builder.Host.UseSerilog((_, _, conf) =>
{
    if (!string.IsNullOrEmpty(commonOptions.OtelExporterOtlpEndpoint))
        conf.AddOtel(builder.Environment.ApplicationName, Environment.MachineName, builder.Environment.EnvironmentName,
            commonOptions.OtelExporterOtlpEndpoint);
    conf.WriteTo.Console();
});

if (!string.IsNullOrEmpty(commonOptions.OtelExporterOtlpEndpoint))
    builder.Services.AddOtelTracingAndMetrics(builder.Environment.ApplicationName, Environment.MachineName,
        builder.Environment.EnvironmentName, commonOptions.OtelExporterOtlpEndpoint);

builder.Services.AddControllers();
builder.Services.AddOptions<OidcFedOptions>().Bind(builder.Configuration.GetSection("OidcFederation"));
builder.Services.AddOptions<AuthServerOptions>().Bind(builder.Configuration.GetSection("AuthServer"));
//use in memory cache for development & redis for release
if (builder.Environment.IsDevelopment())
{
    builder.Services.AddDistributedMemoryCache();
}
else
{
    var redisCp = ConnectionMultiplexer.Connect(builder.Configuration["RedisHost"]!);
    builder.Services.AddSingleton<IConnectionMultiplexer>(redisCp);
    builder.Services.AddStackExchangeRedisCache(o =>
        o.ConnectionMultiplexerFactory = () => Task.FromResult<IConnectionMultiplexer>(redisCp));
}

builder.Services.AddHttpClient().ConfigureHttpClientDefaults(def =>
{
    if (!string.IsNullOrEmpty(commonOptions.GematikXAuthHeader))
        def.ConfigurePrimaryHttpMessageHandler(() =>
            new GematikXAuthHttpHandler(commonOptions.GematikXAuthHeader));
});

builder.Services.AddTransient<IFedMasterEntityStatementService, FedMasterEntityStatementService>();
builder.Services.AddTransient<ISectorIdPEntityStatementService, SectorIdPEntityStatementService>();
builder.Services.AddTransient<IFedMasterIdpListService, FedMasterIdpListService>();
builder.Services.AddTransient<ICacheService, CacheService>();
builder.Services.AddTransient<ITokenReplayCache, DistributedTokenReplayCache>();
builder.Services.AddTransient<ITlsClientCertificateService, TlsClientCertificateService>();
builder.Services.AddTransient<ITokenRequestValidator, TokenRequestValidator>();
var fedOptions = builder.Configuration.GetSection("OidcFederation").Get<OidcFedOptions>()!;
builder.Services.AddHttpClient<ISectorIdPmTlsService, SectorIdPmTlsService>(_ => { })
    .ConfigurePrimaryHttpMessageHandler(serv =>
    {
        var certWithKey = serv.GetRequiredService<ITlsClientCertificateService>().GetClientCertificate();
        var handler = string.IsNullOrEmpty(commonOptions.GematikXAuthHeader)
            ? new HttpClientHandler()
            : new GematikXAuthHttpHandler(commonOptions.GematikXAuthHeader);
        handler.ClientCertificates.Add(certWithKey);
        return handler;
    });


// Configure the HTTP request pipeline.
var app = builder.Build();
app.UseSerilogRequestLogging();

var authOptions = app.Services.GetRequiredService<IOptions<AuthServerOptions>>();
app.UseStaticFiles(new StaticFileOptions
{
    RequestPath = $"{new Uri(authOptions.Value.Issuer).LocalPath}/static",
    FileProvider = new SymLinkFileProvider(builder.Environment.WebRootPath)
});

// manual routing because the routes depend on cofigured issuer
// OIDC federation Endpoints
var path = new Uri(fedOptions.Issuer).LocalPath.TrimStart('/');
app.MapControllerRoute("entitystatement", $"{path}/.well-known/openid-federation",
    new { controller = "EntityStatement", action = "Get" });
app.MapControllerRoute("jwks", $"{path}/jwks.jwt", new { controller = "Jwks", action = "Get" });
app.MapControllerRoute("callback", $"{path}/cb", new { controller = "FedCallback", action = "Callback" });

// OIDC Auth Server Endpoints
path = new Uri(authOptions.Value.Issuer).LocalPath.TrimStart('/');
app.MapControllerRoute("discovery", $"{path}/.well-known/openid-configuration",
    new { controller = "DiscoveryEndpoint", action = "Get" });
app.MapControllerRoute("jwksauth", $"{path}/jwks.json", new { controller = "JwksAuth", action = "Get" });
app.MapControllerRoute("auth", $"{path}/auth/Authorize", new { controller = "Authorize", action = "Authorize" });
app.MapControllerRoute("login", $"{path}/auth/Login", new { controller = "Authorize", action = "Login" });
app.MapControllerRoute("token", $"{path}/auth/Token", new { controller = "Token", action = "Post" });
app.MapControllerRoute("userinfo", $"{path}/auth/UserInfo", new { controller = "UserInfo", action = "Get" });

if (builder.Environment.IsDevelopment())
{
    Log.Warning("Running in development mode. FakeLogin enabled!");
    app.MapControllerRoute("fakelogin", $"{path}/auth/FakeLogin", new { controller = "Authorize", action = "FakeLogin" });
}

app.Run();

internal class GematikXAuthHttpHandler(string headerValue) : HttpClientHandler
{
    protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request,
        CancellationToken cancellationToken)
    {
        if (request.RequestUri?.Host == "gsi.dev.gematik.solutions")
            request.Headers.Add("X-Authorization", headerValue);
        return base.SendAsync(request, cancellationToken);
    }
}