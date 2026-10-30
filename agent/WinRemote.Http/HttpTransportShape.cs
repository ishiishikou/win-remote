using System.Net;
using System.Net.Sockets;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Features;

namespace WinRemote.Http;

/// <summary>
/// Narrow transport-shape observation from actual ASP.NET Core HttpContext.
/// Does not authenticate a device, verify TLS certificates, validate CSRF,
/// grant a session, or start a server. Never treat Allowed as access approval.
/// Call only behind Kestrel without ForwardedHeaders or reverse proxies.
/// </summary>
internal static class HttpTransportShape
{
    internal sealed record ExpectedEndpoint(string LocalIpv4, string ClientIpv4, int Port);
    internal sealed record Decision(bool Observed, string Reason)
    {
        internal static Decision Deny(string reason) => new(false, reason);
    }

    internal static Decision Examine(HttpContext? ctx, ExpectedEndpoint? expected)
    {
        if (ctx is null || expected is null ||
            expected.Port is < 1024 or > 65535 ||
            !TryPrivateIpv4(expected.LocalIpv4, out var local) ||
            !TryPrivateIpv4(expected.ClientIpv4, out var client) ||
            local!.Equals(client))
            return Decision.Deny("invalid_endpoint_expectation");

        var request = ctx.Request;
        if (request.Scheme != "https" || !request.IsHttps)
            return Decision.Deny("not_https");

        if (ctx.Connection.LocalIpAddress is not { } actualLocal ||
            actualLocal.AddressFamily != AddressFamily.InterNetwork ||
            !actualLocal.Equals(local) || ctx.Connection.LocalPort != expected.Port ||
            ctx.Connection.RemoteIpAddress is not { } actualRemote ||
            actualRemote.AddressFamily != AddressFamily.InterNetwork ||
            !actualRemote.Equals(client))
            return Decision.Deny("connection_not_exact_lan_endpoint");

        // For a private-LAN-only host there is no supported reverse-proxy hop.
        // Do not let forwarded or rewritten authority bypass the actual socket
        // endpoint. Host MUST still be checked as an untrusted request header.
        foreach (var headerName in request.Headers.Keys)
        {
            if (headerName.Equals("Forwarded", StringComparison.OrdinalIgnoreCase) ||
                headerName.Equals("X-Real-IP", StringComparison.OrdinalIgnoreCase) ||
                headerName.StartsWith("X-Forwarded-", StringComparison.OrdinalIgnoreCase) ||
                headerName.StartsWith("X-Original-", StringComparison.OrdinalIgnoreCase) ||
                headerName.Equals("X-Rewrite-URL", StringComparison.OrdinalIgnoreCase))
                return Decision.Deny("proxy_headers_forbidden");
        }

        string authority = expected.LocalIpv4 + ":" + expected.Port;
        string origin = "https://" + authority;
        var hostHeaders = request.Headers.Host;
        var originHeaders = request.Headers["Origin"];
        if (hostHeaders.Count != 1 || hostHeaders[0] != authority ||
            request.Host.Value != authority ||
            originHeaders.Count != 1 || originHeaders[0] != origin)
            return Decision.Deny("host_or_origin_mismatch");

        if (request.PathBase.HasValue || request.QueryString.HasValue)
            return Decision.Deny("pathbase_or_query_forbidden");

        string? path = request.Path.Value;
        string? rawTarget = ctx.Features.Get<IHttpRequestFeature>()?.RawTarget;
        if (string.IsNullOrEmpty(path) || rawTarget != path)
            return Decision.Deny("raw_target_not_canonical");

        if (path is "/api/input" or "/api/app" or "/api/files")
        {
            if (request.Method != "POST")
                return Decision.Deny("invalid_api_method");
            return new Decision(true, "api_transport_shape_only");
        }

        if (path is "/ws/terminal" or "/ws/screen")
        {
            if (request.Method != "GET")
                return Decision.Deny("invalid_ws_method");
            return new Decision(true, "websocket_transport_shape_only");
        }

        return Decision.Deny("route_not_allowlisted");
    }

    private static bool TryPrivateIpv4(string? text, out IPAddress? ip)
    {
        ip = null;
        if (string.IsNullOrWhiteSpace(text) ||
            !IPAddress.TryParse(text, out var parsed) ||
            parsed.AddressFamily != AddressFamily.InterNetwork ||
            parsed.ToString() != text)
            return false;

        var b = parsed.GetAddressBytes();
        if (!(b[0] == 10 ||
             (b[0] == 172 && b[1] is >= 16 and <= 31) ||
             (b[0] == 192 && b[1] == 168)))
            return false;
        ip = parsed;
        return true;
    }
}
