using System.Security.Cryptography;
using System.Text;

namespace WinRemote.Network;

/// <summary>
/// Process-memory-only one-time WebSocket upgrade ticket for a future TLS host.
/// This class does not expose an HTTP endpoint, WebSocket listener or secret log.
/// It is strictly internal until a trusted local host integrates device/session,
/// CSRF verification, Secure HttpOnly cookies and real network revocation.
/// </summary>
internal sealed class OneTimeWebSocketTicketRegistry : IDisposable
{
    internal enum Channel { Terminal, Screen }
    internal sealed record IssuedTicket(string Secret, TimeSpan IssuedAt);

    private const int MaxFailedAttempts = 5;
    private static readonly TimeSpan TicketLifetime = TimeSpan.FromSeconds(30);
    private readonly object _sync = new();
    private byte[]? _secretDigest;
    private Guid _deviceId;
    private Guid _sessionId;
    private string? _expectedOrigin;
    private Channel _channel;
    private TimeSpan _issuedAt;
    private int _failedAttempts;
    private bool _disposed;

    /// <summary>
    /// This may only be called by the trusted Windows-side host after actual
    /// cookie authentication, local-PC approval and CSRF checks. A new issuance
    /// revokes any pending ticket, even when the new issuance fails.
    /// </summary>
    internal IssuedTicket? Issue(
        Guid deviceId,
        Guid sessionId,
        BrowserRequestBoundary.Endpoint? endpoint,
        Channel channel,
        TimeSpan monotonicNow,
        LocalSessionBoundary.MonotonicSnapshot? session,
        NetworkEpochGuard? networkGate,
        NetworkEpochGuard.Lease? networkLease)
    {
        lock (_sync)
        {
            ClearLocked();
            if (_disposed || deviceId == Guid.Empty || sessionId == Guid.Empty ||
                !IsSafeTime(monotonicNow) || !ValidateEndpoint(endpoint) ||
                !IsSupportedChannel(channel) || networkGate is null ||
                !networkGate.IsActive(networkLease) ||
                !LocalSessionBoundary.Evaluate(session, RequiredCapability(channel)).Allowed)
                return null;

            var random = RandomNumberGenerator.GetBytes(32);
            try
            {
                var secret = Convert.ToBase64String(random)
                    .TrimEnd('=').Replace('+', '-').Replace('/', '_');
                _secretDigest = SHA256.HashData(Encoding.ASCII.GetBytes(secret));
                _deviceId = deviceId;
                _sessionId = sessionId;
                _expectedOrigin = "https://" + endpoint!.LocalIpv4 + ":" + endpoint.Port;
                _channel = channel;
                _issuedAt = monotonicNow;
                return new IssuedTicket(secret, monotonicNow);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(random);
            }
        }
    }

    /// <summary>
    /// Check and consume atomically before upgrading to WSS. This return value
    /// alone is insufficient to authorize a socket: the host must additionally
    /// recheck transport, Origin, cookies, network lease and session throughout.
    /// The upgrade ticket must never appear in URL/query strings or server logs.
    /// </summary>
    internal bool TryConsume(
        string? suppliedSecret,
        Guid deviceId,
        Guid sessionId,
        string? requestOrigin,
        Channel channel,
        TimeSpan monotonicNow,
        LocalSessionBoundary.MonotonicSnapshot? session,
        NetworkEpochGuard? networkGate,
        NetworkEpochGuard.Lease? networkLease)
    {
        lock (_sync)
        {
            if (_disposed || _secretDigest is null)
                return false;

            if (!IsSafeTime(monotonicNow) || monotonicNow < _issuedAt ||
                monotonicNow - _issuedAt >= TicketLifetime ||
                networkGate is null || !networkGate.IsActive(networkLease) ||
                !LocalSessionBoundary.Evaluate(session, RequiredCapability(channel)).Allowed)
            {
                ClearLocked();
                return false;
            }

            bool validContext =
                deviceId == _deviceId && sessionId == _sessionId &&
                IsSupportedChannel(channel) && _channel == channel &&
                string.Equals(requestOrigin, _expectedOrigin, StringComparison.Ordinal);

            // Token consists of 32 random bytes encoded in canonical Base64URL:
            // exactly 43 characters, with the last alphabet index <= 16.
            bool validShape = IsCanonicalToken(suppliedSecret);
            byte[]? digest = validShape
                ? SHA256.HashData(Encoding.ASCII.GetBytes(suppliedSecret!))
                : null;
            bool tokenValid = digest is not null &&
                CryptographicOperations.FixedTimeEquals(_secretDigest, digest);
            if (digest is not null)
                CryptographicOperations.ZeroMemory(digest);

            if (validContext && tokenValid)
            {
                ClearLocked(); // Single-use: atomically consume before returning.
                return true;
            }

            _failedAttempts++;
            if (_failedAttempts >= MaxFailedAttempts)
                ClearLocked();
            return false;
        }
    }

    internal void Revoke()
    {
        lock (_sync) ClearLocked();
    }

    private static bool IsSafeTime(TimeSpan now) =>
        now >= TimeSpan.Zero && now <= TimeSpan.MaxValue - TicketLifetime;

    private static bool ValidateEndpoint(BrowserRequestBoundary.Endpoint? endpoint) =>
        endpoint is not null &&
        System.Net.IPAddress.TryParse(endpoint.LocalIpv4, out var parsed) &&
        parsed.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork &&
        parsed.ToString() == endpoint.LocalIpv4 &&
        endpoint.Port is >= 1024 and <= 65535;

    private static bool IsSupportedChannel(Channel channel) =>
        channel is Channel.Terminal or Channel.Screen;

    private static LocalSessionBoundary.Capability RequiredCapability(Channel channel) =>
        channel == Channel.Terminal
            ? LocalSessionBoundary.Capability.Shell
            : LocalSessionBoundary.Capability.Screen;

    private static bool IsCanonicalToken(string? token)
    {
        if (token is not { Length: 43 } || !token.All(c =>
            c is >= 'A' and <= 'Z' or >= 'a' and <= 'z' or >= '0' and <= '9' or '-' or '_'))
            return false;

        // Canonical unpadded Base64URL representing exactly 32 bytes. Last
        // character has four padding bits zero (indices 0, 16, 32 or 48).
        const string alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        int lastIndex = alphabet.IndexOf(token[42]);
        return lastIndex >= 0 && (lastIndex & 15) == 0;
    }

    private void ClearLocked()
    {
        if (_secretDigest is not null)
            CryptographicOperations.ZeroMemory(_secretDigest);
        _secretDigest = null;
        _deviceId = Guid.Empty;
        _sessionId = Guid.Empty;
        _expectedOrigin = null;
        _issuedAt = default;
        _failedAttempts = 0;
    }

    public void Dispose()
    {
        lock (_sync)
        {
            _disposed = true;
            ClearLocked();
        }
    }
}
