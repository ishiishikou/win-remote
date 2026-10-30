using System.Net;
using System.Net.Sockets;

namespace WinRemote.Network;

/// <summary>
/// Pure request-envelope validation for a future server pipeline. It never
/// starts a listener or grants a live remote operation. Only a trusted HTTPS
/// host should construct these values from actual transport/header/session state.
/// </summary>
internal static class BrowserRequestBoundary
{
    internal sealed record Endpoint(string LocalIpv4, int Port);

    internal sealed record Envelope(
        string? Scheme,
        string? Host,
        string? Origin,
        string? Method,
        string? Path,
        string? ContentType,
        long BodyByteLength,
        bool IsWebSocketUpgrade,
        bool DeviceAuthenticated,
        bool SessionAuthorized,
        bool CsrfVerified,
        bool OneTimeWebSocketTicketVerified);

    internal sealed record Decision(bool Allowed, string Reason)
    {
        internal static Decision Denied(string reason) => new(false, reason);
    }

    // Deliberately assembly-internal. The future Kestrel app must provide
    // independent trusted evidence for these arguments; HTTP headers alone
    // must NEVER set authentication, CSRF, network or session state.
    internal static Decision Evaluate(
        Endpoint? endpoint,
        Envelope? envelope,
        NetworkEpochGuard? network,
        NetworkEpochGuard.Lease? lease)
    {
        if (endpoint is null || envelope is null || network is null ||
            !network.IsActive(lease))
            return Decision.Denied("no_valid_network_epoch");

        if (!IPAddress.TryParse(endpoint.LocalIpv4, out var address) ||
            address.AddressFamily != AddressFamily.InterNetwork ||
            endpoint.LocalIpv4 != address.ToString() ||
            endpoint.Port is < 1024 or > 65535)
            return Decision.Denied("invalid_expected_authority");

        string authority = endpoint.LocalIpv4 + ":" + endpoint.Port;
        string expectedOrigin = "https://" + authority;

        // Compare the raw Host and Origin values strictly to avoid forwarded,
        // trailing-dot, embedded-credentials and parser-normalization ambiguity.
        if (envelope.Scheme != "https" ||
            !string.Equals(envelope.Host, authority, StringComparison.Ordinal) ||
            !string.Equals(envelope.Origin, expectedOrigin, StringComparison.Ordinal))
            return Decision.Denied("untrusted_transport_or_origin");

        if (!envelope.DeviceAuthenticated || !envelope.SessionAuthorized)
            return Decision.Denied("unauthorized_device_or_session");

        if (envelope.IsWebSocketUpgrade)
        {
            if (envelope.Method != "GET" ||
                envelope.Path is not "/ws/terminal" and not "/ws/screen" ||
                envelope.BodyByteLength != 0 ||
                !envelope.OneTimeWebSocketTicketVerified)
                return Decision.Denied("invalid_websocket_upgrade");

            // Ticket must be atomically consumed by a separate trusted service.
            // The browser cannot set custom Authorization headers on a WSS
            // handshake, so a one-time ticket must not be kept in the URL.
            return new Decision(true, "wss_envelope_only");
        }

        // Only unsafe JSON mutation requests are in scope here. GET navigation
        // and static assets will have a separate, no-privilege routing policy.
        if (envelope.Method != "POST" ||
            envelope.Path is not "/api/input" and not "/api/app" and not "/api/files" ||
            envelope.ContentType is not "application/json" and not "application/json; charset=utf-8" ||
            envelope.BodyByteLength is < 0 or > 65536 ||
            !envelope.CsrfVerified)
            return Decision.Denied("invalid_mutation_request");

        return new Decision(true, "post_envelope_only");
    }
}
