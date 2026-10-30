using System.Globalization;
using System.Security.Cryptography;
using System.Text;

namespace WinRemote.Network;

/// <summary>
/// Process-memory-only, single-device authentication proof for a future HTTPS
/// endpoint. No network endpoint, pairing UI, persistent keys or admin permissions.
/// Issuance and verification are assembly-internal until a trusted local approval
/// path and TLS-bound request pipeline are built and reviewed.
/// </summary>
public sealed class LocalDeviceProofRegistry : IDisposable
{
    private readonly object _sync = new();
    private byte[]? _secret;
    private Guid _deviceId;
    private DateTimeOffset _expiresUtc;
    private readonly HashSet<string> _usedNonces = new(StringComparer.Ordinal);
    private bool _disposed;

    private const int MaxNonces = 2048;
    private const long MaximumClockSkewSeconds = 90;

    internal sealed record Enrollment(Guid DeviceId, string SecretHex, DateTimeOffset ExpiresUtc);
    internal sealed record Proof(Guid DeviceId, long UnixSeconds, string NonceHex,
        string Method, string Path, string BodySha256Hex, string MacHex);

    /// <summary>
    /// Must eventually be invoked only from verified physical Windows-user action.
    /// Callers outside this assembly cannot initiate enrollment.
    /// Re-enrollment atomically revokes the previous device and replay window.
    /// </summary>
    internal Enrollment? EnrollLocally(TimeSpan lifetime, DateTimeOffset nowUtc)
    {
        lock (_sync)
        {
            if (_disposed || lifetime < TimeSpan.FromSeconds(30) ||
                lifetime > TimeSpan.FromHours(24))
                return null;

            RevokeLocked();
            _secret = RandomNumberGenerator.GetBytes(32);
            _deviceId = Guid.NewGuid();
            _expiresUtc = nowUtc.Add(lifetime);
            // The secret is returned once to a future local-only pairing UI.
            // Never print, persist, or send it without authenticated local consent.
            return new Enrollment(_deviceId, Convert.ToHexString(_secret).ToLowerInvariant(), _expiresUtc);
        }
    }

    internal bool Verify(Proof? proof, DateTimeOffset trustedNowUtc)
    {
        lock (_sync)
        {
            if (_disposed || proof is null || _secret is null ||
                _deviceId != proof.DeviceId)
                return false;

            if (trustedNowUtc >= _expiresUtc)
            {
                RevokeLocked();
                return false;
            }

            var now = trustedNowUtc.ToUnixTimeSeconds();
            if (proof.UnixSeconds < now - MaximumClockSkewSeconds ||
                proof.UnixSeconds > now + MaximumClockSkewSeconds ||
                !IsLowerHex(proof.NonceHex, 32) ||
                !IsLowerHex(proof.BodySha256Hex, 64) ||
                !IsLowerHex(proof.MacHex, 64) ||
                !IsValidMethodPath(proof.Method, proof.Path) ||
                _usedNonces.Contains(proof.NonceHex) ||
                _usedNonces.Count >= MaxNonces)
                return false;

            var message = Encoding.UTF8.GetBytes(SigningMessage(proof));
            byte[] expected = HMACSHA256.HashData(_secret, message);
            byte[] received = Convert.FromHexString(proof.MacHex);
            var valid = CryptographicOperations.FixedTimeEquals(expected, received);
            CryptographicOperations.ZeroMemory(expected);
            CryptographicOperations.ZeroMemory(received);
            if (!valid) return false;

            // A valid MAC can be used only once, even if path/body are repeated.
            _usedNonces.Add(proof.NonceHex);
            return true;
        }
    }

    internal static string SigningMessage(Proof proof) =>
        "v1\n" + proof.DeviceId.ToString("D") + "\n" +
        proof.UnixSeconds.ToString(CultureInfo.InvariantCulture) + "\n" +
        proof.NonceHex + "\n" + proof.Method + "\n" + proof.Path +
        "\n" + proof.BodySha256Hex;

    private static bool IsLowerHex(string? value, int expectedLength) =>
        value is not null && value.Length == expectedLength &&
        value.All(ch => (ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f'));

    private static bool IsValidMethodPath(string? method, string? path) =>
        (method is "GET" or "POST") &&
        path is not null && path.Length is >= 5 and <= 256 &&
        path.StartsWith("/api/", StringComparison.Ordinal) &&
        !path.Contains("//", StringComparison.Ordinal) &&
        path.AsSpan().ToArray().All(ch =>
            (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') ||
            (ch >= '0' && ch <= '9') || ch is '/' or '-' or '_');

    public void Revoke()
    {
        lock (_sync) RevokeLocked();
    }

    private void RevokeLocked()
    {
        if (_secret is not null)
            CryptographicOperations.ZeroMemory(_secret);
        _secret = null;
        _deviceId = Guid.Empty;
        _expiresUtc = default;
        _usedNonces.Clear();
    }

    public void Dispose()
    {
        lock (_sync)
        {
            _disposed = true;
            RevokeLocked();
        }
    }
}
