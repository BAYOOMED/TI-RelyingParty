using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using Com.Bayoomed.TelematikFederation;
using Com.Bayoomed.TelematikFederation.Controllers.OidcAuthServer;
using Com.Bayoomed.TelematikFederation.Controllers.OidcFederation;
using Com.Bayoomed.TelematikFederation.Logging;
using Com.Bayoomed.TelematikFederation.OidcRequest;
using Com.Bayoomed.TelematikFederation.OidcResponse;
using Com.Bayoomed.TelematikFederation.Services;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Moq;
using Serilog;
using Serilog.Core;
using Serilog.Events;
using Serilog.Extensions.Logging;
using Serilog.Formatting;
using Serilog.Formatting.Display;
using Match = System.Text.RegularExpressions.Match;

namespace RelyingParty.Test;

/// <summary>
///     The GidLoginResult line is a contract with the Grafana/Loki alert: exactly one line per finished login step,
///     a fixed format and classified results.
/// </summary>
[TestClass]
public class GidLoginResultTest
{
    // Serilog's default console output template (Program.cs uses WriteTo.Console() without a template)
    private const string ConsoleTemplate = "[{Timestamp:HH:mm:ss} {Level:u3}] {Message:lj}{NewLine}{Exception}";

    private const string LinePattern =
        @"^\[\d\d:\d\d:\d\d INF\] GidLoginResult Result=(?<result>\S+) Stage=(?<stage>\S+) ErrorCode=(?<code>\S+) ElapsedMs=\d+$";

    private const string SecIdpIss = "https://sectoridp.example";

    private StringWriter _output = null!;
    private SerilogLoggerFactory _factory = null!;

    [TestInitialize]
    public void Init()
    {
        _output = new StringWriter();
        var serilog = new LoggerConfiguration().MinimumLevel.Information()
            .WriteTo.Sink(new TextSink(_output, new MessageTemplateTextFormatter(ConsoleTemplate))).CreateLogger();
        _factory = new SerilogLoggerFactory(serilog, true);
    }

    [TestCleanup]
    public void Cleanup()
    {
        _factory.Dispose();
    }

    private ILogger<T> Logger<T>() => _factory.CreateLogger<T>();

    private List<string> ResultLines()
    {
        return _output.ToString().Split(Environment.NewLine)
            .Where(l => l.Contains("] GidLoginResult ")).ToList();
    }

    private Match SingleResultLine()
    {
        var lines = ResultLines();
        Assert.AreEqual(1, lines.Count, string.Join(Environment.NewLine, lines));
        var match = Regex.Match(lines[0], LinePattern);
        Assert.IsTrue(match.Success, $"unexpected format: {lines[0]}");
        return match;
    }

    private static void AssertLine(Match line, string result, string stage, string code)
    {
        Assert.AreEqual(result, line.Groups["result"].Value);
        Assert.AreEqual(stage, line.Groups["stage"].Value);
        Assert.AreEqual(code, line.Groups["code"].Value);
    }

    // ---------- format ----------

    [TestMethod]
    public void ResultLine_RenderedBySerilog_HasFormatExpectedByAlert()
    {
        var result = new GidLoginResult(GidLoginResult.StageCallback);
        result.Set(GidLoginResult.Success);
        result.Write(Logger<GidLoginResultTest>());

        var line = ResultLines().Single();
        Assert.IsFalse(line.Contains('"'), line);
        Assert.IsTrue(Regex.IsMatch(line,
            @"^\[\d\d:\d\d:\d\d INF\] GidLoginResult Result=Success Stage=Callback ErrorCode=none ElapsedMs=\d+$"),
            line);
    }

    [TestMethod]
    public void Write_LoggerThrows_DoesNotThrow()
    {
        var logger = new Mock<Microsoft.Extensions.Logging.ILogger>();
        logger.Setup(l => l.IsEnabled(It.IsAny<LogLevel>())).Returns(true);
        logger.Setup(l => l.Log(It.IsAny<LogLevel>(), It.IsAny<EventId>(), It.IsAny<It.IsAnyType>(),
                It.IsAny<Exception?>(), It.IsAny<Func<It.IsAnyType, Exception?, string>>()))
            .Throws(new InvalidOperationException());
        new GidLoginResult(GidLoginResult.StageToken).Write(logger.Object);
    }

    // ---------- Authorize stage ----------

    private static IOptions<AuthServerOptions> AuthOptions()
    {
        return Options.Create(new AuthServerOptions
        {
            Issuer = "https://issuer/xyz",
            SignPrivKey = ECDsa.Create(ECCurve.NamedCurves.nistP256).ExportECPrivateKeyPem(),
            Clients = new List<OidcClient>
            {
                new()
                {
                    ClientId = "client",
                    ClientSecret = "secret",
                    RedirectUris = new List<string> { "https://redirect" }
                }
            }
        });
    }

    private static AuthorizationRequest ValidAuthRequest(string? loginHint = null)
    {
        return new AuthorizationRequest
        {
            client_id = "client",
            redirect_uri = "https://redirect",
            response_type = "code",
            scope = "openid",
            state = "state",
            nonce = "nonce",
            code_challenge = "challenge",
            code_challenge_method = "S256",
            login_hint = loginHint
        };
    }

    private AuthorizeController AuthorizeController(Mock<ICacheService> cache, Mock<ISectorIdPmTlsService>? par = null)
    {
        var idpList = new Mock<IFedMasterIdpListService>();
        idpList.Setup(l => l.GetIdpListAsync()).ReturnsAsync(new List<IdpEntry> { new() { iss = SecIdpIss } });
        return new AuthorizeController(AuthOptions(), cache.Object, (par ?? new Mock<ISectorIdPmTlsService>()).Object,
            idpList.Object, Logger<AuthorizeController>());
    }

    private static Mock<ISectorIdPmTlsService> ParService()
    {
        var par = new Mock<ISectorIdPmTlsService>();
        par.Setup(p => p.SendPushedAuthorizationRequest(It.IsAny<string>(), It.IsAny<string>(), It.IsAny<string?>(),
                It.IsAny<string?>(), It.IsAny<string?>()))
            .ReturnsAsync(new ParResponse(new AuthorizationRequest(), "verifier", "https://sectoridp.example/auth",
                SecIdpIss));
        return par;
    }

    [TestMethod]
    public async Task Authorize_UnknownClient_LogsClientError()
    {
        var request = ValidAuthRequest();
        request.client_id = "unknown";
        var resp = await AuthorizeController(new Mock<ICacheService>()).Authorize(request);

        Assert.IsInstanceOfType(resp, typeof(BadRequestObjectResult));
        AssertLine(SingleResultLine(), "ClientError", "Authorize", "invalid_client");
    }

    [TestMethod]
    public async Task Authorize_InvalidScope_LogsClientError()
    {
        var request = ValidAuthRequest();
        request.scope = "profile";
        var resp = await AuthorizeController(new Mock<ICacheService>()).Authorize(request);

        Assert.IsInstanceOfType(resp, typeof(RedirectResult));
        AssertLine(SingleResultLine(), "ClientError", "Authorize", "invalid_scope");
    }

    [TestMethod]
    public async Task Authorize_ValidRequestShowingLoginPage_LogsNothing()
    {
        var cache = new Mock<ICacheService>();
        cache.Setup(c => c.AddAuthorizationRequest(It.IsAny<AuthorizationRequest>(), null)).ReturnsAsync("code");
        var resp = await AuthorizeController(cache).Authorize(ValidAuthRequest());

        Assert.IsInstanceOfType(resp, typeof(RedirectResult));
        Assert.AreEqual(0, ResultLines().Count);
    }

    [TestMethod]
    public async Task Authorize_WithLoginHint_LogsExactlyOneLine()
    {
        var cache = new Mock<ICacheService>();
        cache.Setup(c => c.AddAuthorizationRequest(It.IsAny<AuthorizationRequest>(), It.IsAny<string?>()))
            .ReturnsAsync("code");
        cache.Setup(c => c.GetAuthorizationRequest("code")).ReturnsAsync(ValidAuthRequest());
        var hint = new IdpEntry { iss = SecIdpIss }.id;
        await AuthorizeController(cache, ParService()).Authorize(ValidAuthRequest(hint));

        AssertLine(SingleResultLine(), "Success", "Authorize", "none");
    }

    [TestMethod]
    public async Task Authorize_CacheThrows_LogsTechnicalFailureAndRethrows()
    {
        var cache = new Mock<ICacheService>();
        cache.Setup(c => c.AddAuthorizationRequest(It.IsAny<AuthorizationRequest>(), It.IsAny<string?>()))
            .ThrowsAsync(new TimeoutException("redis"));

        await Assert.ThrowsExactlyAsync<TimeoutException>(() =>
            AuthorizeController(cache).Authorize(ValidAuthRequest()));
        AssertLine(SingleResultLine(), "TechnicalFailure", "Authorize", "unhandled_exception");
    }

    [TestMethod]
    public async Task Login_SessionExpired_LogsUserAborted()
    {
        var resp = await AuthorizeController(new Mock<ICacheService>()).Login("code", "idp");

        Assert.IsInstanceOfType(resp, typeof(BadRequestObjectResult));
        AssertLine(SingleResultLine(), "UserAborted", "Authorize", "session_expired");
    }

    [TestMethod]
    public async Task Login_UnknownIdp_LogsClientError()
    {
        var cache = new Mock<ICacheService>();
        cache.Setup(c => c.GetAuthorizationRequest("code")).ReturnsAsync(ValidAuthRequest());
        var resp = await AuthorizeController(cache).Login("code", "unknown");

        Assert.IsInstanceOfType(resp, typeof(BadRequestResult));
        AssertLine(SingleResultLine(), "ClientError", "Authorize", "unknown_idp");
    }

    [TestMethod]
    public async Task Login_ParFails_LogsIdpError()
    {
        var cache = new Mock<ICacheService>();
        cache.Setup(c => c.GetAuthorizationRequest("code")).ReturnsAsync(ValidAuthRequest());
        var par = new Mock<ISectorIdPmTlsService>();
        par.Setup(p => p.SendPushedAuthorizationRequest(It.IsAny<string>(), It.IsAny<string>(), It.IsAny<string?>(),
                It.IsAny<string?>(), It.IsAny<string?>()))
            .ThrowsAsync(new HttpRequestException("unreachable"));
        var resp = await AuthorizeController(cache, par).Login("code", new IdpEntry { iss = SecIdpIss }.id);

        Assert.IsInstanceOfType(resp, typeof(RedirectResult));
        StringAssert.Contains(((RedirectResult)resp).Url, "error=server_error");
        AssertLine(SingleResultLine(), "IdpError", "Authorize", "par_failed");
    }

    [TestMethod]
    public async Task Login_IdpListFails_LogsTechnicalFailure()
    {
        var cache = new Mock<ICacheService>();
        cache.Setup(c => c.GetAuthorizationRequest("code")).ReturnsAsync(ValidAuthRequest());
        var idpList = new Mock<IFedMasterIdpListService>();
        idpList.Setup(l => l.GetIdpListAsync()).ThrowsAsync(new HttpRequestException("fed master down"));
        var cnt = new AuthorizeController(AuthOptions(), cache.Object, new Mock<ISectorIdPmTlsService>().Object,
            idpList.Object, Logger<AuthorizeController>());
        await cnt.Login("code", "idp");

        AssertLine(SingleResultLine(), "TechnicalFailure", "Authorize", "idp_list_failed");
    }

    [TestMethod]
    public async Task Login_Success_LogsSuccess()
    {
        var cache = new Mock<ICacheService>();
        cache.Setup(c => c.GetAuthorizationRequest("code")).ReturnsAsync(ValidAuthRequest());
        var resp = await AuthorizeController(cache, ParService()).Login("code", new IdpEntry { iss = SecIdpIss }.id);

        Assert.AreEqual("https://sectoridp.example/auth", ((RedirectResult)resp).Url);
        AssertLine(SingleResultLine(), "Success", "Authorize", "none");
    }

    // ---------- Callback stage ----------

    private FedCallbackController CallbackController(Mock<ICacheService> cache,
        Mock<ISectorIdPEntityStatementService>? es = null)
    {
        return new FedCallbackController(cache.Object,
            Options.Create(new OidcFedOptions { Issuer = "https://fedissuer" }), AuthOptions(),
            (es ?? new Mock<ISectorIdPEntityStatementService>()).Object, new Mock<ISectorIdPmTlsService>().Object,
            Logger<FedCallbackController>());
    }

    private static Mock<ICacheService> CallbackCache()
    {
        var cache = new Mock<ICacheService>();
        cache.Setup(c => c.GetAndRemoveParResponse("state")).ReturnsAsync(
            new ParResponse(new AuthorizationRequest { nonce = "nonce" }, "verifier", "https://x", SecIdpIss));
        cache.Setup(c => c.GetAndRemoveAuthorizationRequest("state")).ReturnsAsync(ValidAuthRequest());
        return cache;
    }

    [TestMethod]
    public async Task Callback_SessionExpired_LogsUserAborted()
    {
        var resp = await CallbackController(new Mock<ICacheService>()).Callback("code", "state", null, null);

        Assert.IsInstanceOfType(resp, typeof(BadRequestObjectResult));
        AssertLine(SingleResultLine(), "UserAborted", "Callback", "session_expired");
    }

    [TestMethod]
    public async Task Callback_AccessDenied_LogsUserAborted()
    {
        await CallbackController(CallbackCache()).Callback(null, "state", "access_denied", "user cancelled");

        AssertLine(SingleResultLine(), "UserAborted", "Callback", "access_denied");
    }

    [TestMethod]
    public async Task Callback_OtherIdpError_LogsIdpError()
    {
        var resp = await CallbackController(CallbackCache())
            .Callback(null, "state", "temporarily_unavailable", null);

        StringAssert.Contains(((RedirectResult)resp).Url, "error=server_error");
        AssertLine(SingleResultLine(), "IdpError", "Callback", "temporarily_unavailable");
    }

    [TestMethod]
    public async Task Callback_NoCodeNoError_LogsIdpError()
    {
        await CallbackController(CallbackCache()).Callback(null, "state", null, null);

        AssertLine(SingleResultLine(), "IdpError", "Callback", "missing_code");
    }

    [TestMethod]
    public async Task Callback_EntityStatementFails_LogsIdpError()
    {
        var es = new Mock<ISectorIdPEntityStatementService>();
        es.Setup(s => s.GetSectorIdPEntityStatement(It.IsAny<string>(), It.IsAny<bool>()))
            .ThrowsAsync(new HttpRequestException("unreachable"));
        var resp = await CallbackController(CallbackCache(), es).Callback("code", "state", null, null);

        StringAssert.Contains(((RedirectResult)resp).Url, "error=server_error");
        AssertLine(SingleResultLine(), "IdpError", "Callback", "idp_entity_statement_failed");
    }

    [TestMethod]
    public async Task Callback_RedisUnreachable_LogsTechnicalFailureAndRethrows()
    {
        var cache = new Mock<ICacheService>();
        cache.Setup(c => c.GetAndRemoveParResponse(It.IsAny<string>())).ThrowsAsync(new TimeoutException("redis"));

        await Assert.ThrowsExactlyAsync<TimeoutException>(() =>
            CallbackController(cache).Callback("code", "state", null, null));
        AssertLine(SingleResultLine(), "TechnicalFailure", "Callback", "unhandled_exception");
    }

    // ---------- Token stage ----------

    private TokenController TokenController(Mock<ICacheService> cache)
    {
        var options = AuthOptions();
        return new TokenController(options, cache.Object, Logger<TokenController>(),
            new TokenRequestValidator(options));
    }

    private static Mock<ICacheService> TokenCache()
    {
        var cache = new Mock<ICacheService>();
        var authRequest = ValidAuthRequest();
        authRequest.code_challenge = Base64UrlEncoder.Encode(SHA256.HashData("verifier"u8.ToArray()));
        cache.Setup(c => c.GetAndRemoveAuthorizationRequest("code")).ReturnsAsync(authRequest);
        cache.Setup(c => c.GetAndRemoveIdTokenFromSectorIdP("code")).ReturnsAsync(new JwtPayload(new Claim[]
        {
            new("iss", SecIdpIss),
            new("sub", "SECRET-SUB"),
            new("urn:telematik:claims:id", "A123456789")
        }));
        return cache;
    }

    private static TokenRequest ValidTokenRequest()
    {
        return new TokenRequest
        {
            code = "code",
            client_id = "client",
            client_secret = "secret",
            grant_type = "authorization_code",
            redirect_uri = "https://redirect",
            code_verifier = "verifier"
        };
    }

    [TestMethod]
    public async Task Token_Success_LogsOnlyResultData()
    {
        var resp = await TokenController(TokenCache()).Post(ValidTokenRequest(), string.Empty);

        Assert.IsInstanceOfType(resp, typeof(JsonResult));
        var tokenResponse = (TokenResponse)((JsonResult)resp).Value!;
        AssertLine(SingleResultLine(), "Success", "Token", "none");
        var line = ResultLines().Single();
        foreach (var personal in new[]
                 {
                     "SECRET-SUB", "A123456789", "secret", "verifier", "nonce", "state", "challenge", SecIdpIss, "client",
                     tokenResponse.access_token, tokenResponse.id_token
                 })
            Assert.IsFalse(line.Contains(personal), $"line contains '{personal}': {line}");
    }

    [TestMethod]
    public async Task Token_CodeNotInCache_LogsClientError()
    {
        var resp = await TokenController(new Mock<ICacheService>()).Post(ValidTokenRequest(), string.Empty);

        Assert.IsInstanceOfType(resp, typeof(BadRequestObjectResult));
        AssertLine(SingleResultLine(), "ClientError", "Token", "invalid_grant");
    }

    [TestMethod]
    public async Task Token_WrongSecret_LogsClientError()
    {
        var request = ValidTokenRequest();
        request.client_secret = "wrong";
        var resp = await TokenController(TokenCache()).Post(request, string.Empty);

        Assert.IsInstanceOfType(resp, typeof(UnauthorizedObjectResult));
        AssertLine(SingleResultLine(), "ClientError", "Token", "invalid_client");
    }

    [TestMethod]
    public async Task Token_PkceMismatch_LogsClientError()
    {
        var request = ValidTokenRequest();
        request.code_verifier = "other";
        await TokenController(TokenCache()).Post(request, string.Empty);

        AssertLine(SingleResultLine(), "ClientError", "Token", "invalid_grant");
    }

    [TestMethod]
    public async Task Token_MalformedBasicAuth_StillThrows_AndLogsTechnicalFailure()
    {
        // existing behaviour (unhandled FormatException -> 500) is kept on purpose
        await Assert.ThrowsExactlyAsync<FormatException>(() =>
            TokenController(TokenCache()).Post(ValidTokenRequest(), "Basic not-base64!"));
        AssertLine(SingleResultLine(), "TechnicalFailure", "Token", "unhandled_exception");
    }

    [TestMethod]
    public async Task Token_BasicAuth_UsesClientIdFromHeader()
    {
        var request = ValidTokenRequest();
        request.client_id = null;
        request.client_secret = null;
        var header = "Basic " + Convert.ToBase64String(Encoding.UTF8.GetBytes("client:secret"));
        var resp = await TokenController(TokenCache()).Post(request, header);

        Assert.IsInstanceOfType(resp, typeof(JsonResult));
        AssertLine(SingleResultLine(), "Success", "Token", "none");
    }

    // renders events with the same formatter the Serilog console sink uses
    private sealed class TextSink(TextWriter writer, ITextFormatter formatter) : ILogEventSink
    {
        public void Emit(LogEvent logEvent)
        {
            formatter.Format(logEvent, writer);
        }
    }
}
