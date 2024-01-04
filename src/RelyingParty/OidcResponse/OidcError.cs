using System.Diagnostics.CodeAnalysis;

namespace Com.Bayoomed.TelematikFederation.OidcResponse;

[SuppressMessage("ReSharper", "InconsistentNaming")]
public enum OidcError
{
    invalid_client,
    redirect_uri_mismatch,
    invalid_request,
    unauthorized_client,
    access_denied,
    unsupported_response_type,
    invalid_scope,
    server_error,
    invalid_grant,
    unsupported_grant_type
}