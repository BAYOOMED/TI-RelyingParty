using System.Diagnostics;

namespace Com.Bayoomed.TelematikFederation.Logging;

/// <summary>
///     Collects the outcome of one finished login step and writes exactly one structured
///     <c>GidLoginResult</c> line for it. Ops alerts on this line in Loki, so the format is a contract:
///     do not change the marker, the keys or their order without changing the alert as well.
///     Values are passed as strings (not enums) so Serilog renders them without quotes.
///     Only data that was already logged before is included: no client id, no IdP, no user data.
/// </summary>
public sealed class GidLoginResult(string stage)
{
    internal const string Template =
        "GidLoginResult Result={Result} Stage={Stage} ErrorCode={ErrorCode} ElapsedMs={ElapsedMs}";

    // stages
    public const string StageAuthorize = "Authorize";
    public const string StageCallback = "Callback";
    public const string StageToken = "Token";

    // results
    public const string Success = "Success";
    public const string UserAborted = "UserAborted";
    public const string ClientError = "ClientError";
    public const string IdpError = "IdpError";
    public const string TechnicalFailure = "TechnicalFailure";

    private readonly long _start = Stopwatch.GetTimestamp();
    private bool _skip;

    public string Stage { get; } = stage;

    /// <summary>Defaults to TechnicalFailure, so an exception nobody expected is reported as our fault.</summary>
    public string Result { get; private set; } = TechnicalFailure;

    public string? ErrorCode { get; private set; } = "unhandled_exception";

    /// <summary>
    ///     Sets the classification. Called after a step finished, or before a section of code to say
    ///     how an exception thrown inside it is classified.
    /// </summary>
    public void Set(string result, string? errorCode = null)
    {
        Result = result;
        ErrorCode = errorCode;
    }

    /// <summary>The step did not finish here (e.g. the user is shown the IdP selection page); write no line.</summary>
    public void Skip()
    {
        _skip = true;
    }

    /// <summary>Writes the line. Never throws, so logging can not fail a request.</summary>
    public void Write(ILogger logger)
    {
        if (_skip)
            return;
        try
        {
            logger.LogInformation(Template, Result, Stage, OrNone(ErrorCode),
                (long)Stopwatch.GetElapsedTime(_start).TotalMilliseconds);
        }
        catch
        {
            // logging must never change the response
        }
    }

    /// <summary>A missing value is logged as "none".</summary>
    private static string OrNone(string? value)
    {
        return string.IsNullOrEmpty(value) ? "none" : value;
    }
}
