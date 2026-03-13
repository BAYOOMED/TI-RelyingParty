using Com.Bayoomed.TelematikFederation;
using Com.Bayoomed.TelematikFederation.Services;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Serilog;
using StackExchange.Redis;
using System.Security.Cryptography;

var builder = WebApplication.CreateBuilder(args);
var commonOptions = builder.Configuration.Get<CommonOptions>()!;
builder.Host.UseSerilog((ctx, _, conf) =>
{
    conf.ReadFrom.Configuration(ctx.Configuration);
    conf.WriteTo.Console();
});

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

// A_27585: Validate redirect_uris at startup
foreach (var uri in fedOptions.RedirectUris ?? [$"{fedOptions.Issuer}/cb"])
{
    if (!Uri.TryCreate(uri, UriKind.Absolute, out var parsed))
        throw new InvalidOperationException($"A_27585: redirect_uri '{uri}' is not a valid absolute URI.");
    if (!builder.Environment.IsDevelopment() && parsed.Scheme != "https")
        throw new InvalidOperationException($"A_27585: redirect_uri '{uri}' must use HTTPS.");
    if (!string.IsNullOrEmpty(parsed.Query))
        throw new InvalidOperationException($"A_27585: redirect_uri '{uri}' must not contain a query part.");
    if (!string.IsNullOrEmpty(parsed.Fragment))
        throw new InvalidOperationException($"A_27585: redirect_uri '{uri}' must not contain a fragment.");
    if (!string.IsNullOrEmpty(parsed.UserInfo))
        throw new InvalidOperationException($"A_27585: redirect_uri '{uri}' must not contain user credentials.");
}

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

//add CORS policy for /idp endpoint (Access-Control-Allow-Origin: *)
builder.Services.AddCors(options =>
{
    options.AddPolicy("idplist",
        policy => { policy.AllowAnyOrigin(); });
});

// Configure the HTTP request pipeline.
var app = builder.Build();

// A_28208: Auto-generate UUID v7 key identifiers (persisted in distributed cache by key thumbprint)
var cache = app.Services.GetRequiredService<IDistributedCache>();
var fedOpts = app.Services.GetRequiredService<IOptions<OidcFedOptions>>().Value;
fedOpts.SignPrivKeyId = ResolveKeyId(cache, fedOpts.SignPrivKey);
fedOpts.EncPrivKeyId = ResolveKeyId(cache, fedOpts.EncPrivKey);
if (!string.IsNullOrEmpty(fedOpts.NextSignPrivKey))
    fedOpts.NextSignPrivKeyId = ResolveKeyId(cache, fedOpts.NextSignPrivKey);
var authOpts = app.Services.GetRequiredService<IOptions<AuthServerOptions>>().Value;
authOpts.SignPrivKeyId = ResolveKeyId(cache, authOpts.SignPrivKey);

// A_23185-01: Validate key age does not exceed 398 days
const int maxKeyAgeDays = 398;
ValidateKeyAge(fedOpts.SignPrivKeyId, "OidcFederation:SignPrivKey", maxKeyAgeDays);
ValidateKeyAge(fedOpts.EncPrivKeyId, "OidcFederation:EncPrivKey", maxKeyAgeDays);
ValidateKeyAge(authOpts.SignPrivKeyId, "AuthServer:SignPrivKey", maxKeyAgeDays);

app.UseSerilogRequestLogging();

var authOptions = app.Services.GetRequiredService<IOptions<AuthServerOptions>>();
app.UseStaticFiles(new StaticFileOptions
{
    RequestPath = $"{new Uri(authOptions.Value.Issuer).LocalPath}/static",
    FileProvider = new SymLinkFileProvider(builder.Environment.WebRootPath)
});
app.UseCors();
// manual routing because the routes depend on configured issuer
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
    app.MapControllerRoute("fakelogin", $"{path}/auth/FakeLogin",
        new { controller = "Authorize", action = "FakeLogin" });
}

app.Run();

// A_28208: Resolve or create a UUID v7 key identifier for a PEM key, cached by JWK thumbprint
static string ResolveKeyId(IDistributedCache cache, string pemKey)
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

// A_23185-01: Validate key age based on UUID v7 timestamp
static void ValidateKeyAge(string keyId, string keyName, int maxDays)
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

static DateTimeOffset GetUuid7Timestamp(Guid uuid)
{
    Span<byte> bytes = stackalloc byte[16];
    uuid.TryWriteBytes(bytes, bigEndian: true, out _);
    long unixMs = ((long)bytes[0] << 40) | ((long)bytes[1] << 32) | ((long)bytes[2] << 24) |
                  ((long)bytes[3] << 16) | ((long)bytes[4] << 8) | bytes[5];
    return DateTimeOffset.FromUnixTimeMilliseconds(unixMs);
}

internal class GematikXAuthHttpHandler(string headerValue) : HttpClientHandler
{
    protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request,
        CancellationToken cancellationToken)
    {
        if (request.RequestUri != null && request.RequestUri.Host.EndsWith("gematik.solutions", StringComparison.OrdinalIgnoreCase))
            request.Headers.Add("X-Authorization", headerValue);
        return base.SendAsync(request, cancellationToken);
    }
}