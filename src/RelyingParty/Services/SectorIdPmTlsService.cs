using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Web;
using Com.Bayoomed.TelematikFederation.OidcRequest;
using Com.Bayoomed.TelematikFederation.OidcResponse;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

namespace Com.Bayoomed.TelematikFederation.Services;

public record ParResponse(AuthorizationRequest Request, string CodeVerifier, string RedirectUri,
    string SecIdpIss);

public class SectorIdPmTlsService(ISectorIdPEntityStatementService esService, IOptions<OidcFedOptions> options,
    HttpClient client) : ISectorIdPmTlsService
{
    private readonly string _iss = options.Value.Issuer;

    public async Task<ParResponse> SendPushedAuthorizationRequest(string iss, string state, string? scope)
    {
        if(string.IsNullOrEmpty(scope))
            scope = options.Value.Scope;
        var (challenge, verifier) = GenerateCodeChallenge();
        var authReq = new AuthorizationRequest
        {
            response_type = "code",
            client_id = _iss,
            redirect_uri = $"{_iss}/cb",
            scope = scope,
            state = state,
            nonce = Base64UrlEncoder.Encode(RandomNumberGenerator.GetBytes(32)),
            code_challenge = challenge,
            code_challenge_method = "S256",
            acr_values = "gematik-ehealth-loa-high"
        };
        var dict = JsonSerializer.Deserialize<Dictionary<string, string>>(JsonSerializer.Serialize(authReq));
        var content = new FormUrlEncodedContent(dict!);
        var esSec = await esService.GetSectorIdPEntityStatement(iss);

        var resp = await client.PostAsync(esSec.GetParEndpoint(), content);
        if (resp.StatusCode == HttpStatusCode.Unauthorized)
        {
            await Task.Delay(1500);
            resp = await client.PostAsync(esSec.GetParEndpoint(), content);
        }

        if (!resp.IsSuccessStatusCode)
            throw new Exception($"failed to send PAR: {resp.StatusCode} {await resp.Content.ReadAsStringAsync()}");
        var auth = await resp.Content.ReadFromJsonAsync<AuthorizationResponse>();
        if (auth == null)
            throw new Exception($"unable to read PAR response for iss: {iss}");
        var redirectUri = new UriBuilder(esSec.GetAuthorizationEndpoint() ??
                                         throw new Exception("no auth endpoint in sec idp ES statement"));
        var query = HttpUtility.ParseQueryString(redirectUri.Query);
        query["request_uri"] = auth.request_uri;
        query["client_id"] = _iss;
        redirectUri.Query = query.ToString();
        return new ParResponse(authReq, verifier, redirectUri.ToString(), iss);
    }

    public async Task<string> SendTokenRequest(TokenRequest request, string tokenEndpoint)
    {
        var dict = JsonSerializer.Deserialize<Dictionary<string, string>>(JsonSerializer.Serialize(request));
        var content = new FormUrlEncodedContent(dict!);
        var resp = await client.PostAsync(tokenEndpoint, content);
        if (!resp.IsSuccessStatusCode)
            throw new Exception(
                $"failed to send token request: {resp.StatusCode} {await resp.Content.ReadAsStringAsync()}");
        var tkResp = await resp.Content.ReadFromJsonAsync<TokenResponse>();
        if (tkResp?.id_token == null)
            throw new Exception($"unable to read id_token response for iss: {tokenEndpoint}");
        return tkResp.id_token;
    }

    private (string, string) GenerateCodeChallenge()
    {
        var verifier = Base64UrlEncoder.Encode(RandomNumberGenerator.GetBytes(32));
        var challenge = Base64UrlEncoder.Encode(SHA256.HashData(Encoding.ASCII.GetBytes(verifier)));
        return (challenge, verifier);
    }
}