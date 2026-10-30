using System.Security.Cryptography;
using System.Text;

namespace WinRemote.Network;

/// <summary>
/// Local-only pairing challenge state, never a reachable enrollment endpoint.
/// Creating an offer and approving a match must eventually require explicit
/// Windows tray interaction; a match alone does NOT register a device.
/// </summary>
internal sealed class LocalPairingCodeWindow : IDisposable
{
    private const string Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    private static readonly TimeSpan Lifetime = TimeSpan.FromMinutes(2);
    private readonly object _sync = new();
    private byte[]? _codeAscii;
    private Guid _offerId;
    private TimeSpan _issuedAt;
    private int _failedAttempts;
    private bool _awaitingPcApproval;
    private bool _disposed;

    internal sealed record LocalOffer(Guid Id, string DisplayCode);

    /// <summary>
    /// Only a trusted local Windows UI may call this method, never HTTP input.
    /// Another call supersedes and invalidates the previous challenge.
    /// </summary>
    internal LocalOffer? BeginLocally(TimeSpan monotonicNow)
    {
        lock (_sync)
        {
            InvalidateLocked();
            if (_disposed || monotonicNow < TimeSpan.Zero ||
                monotonicNow > TimeSpan.MaxValue - Lifetime)
                return null;

            var random = RandomNumberGenerator.GetBytes(10); // 80 bits
            try
            {
                string code = EncodeBase32(random);
                _codeAscii = Encoding.ASCII.GetBytes(code);
                _offerId = Guid.NewGuid();
                _issuedAt = monotonicNow;
                return new LocalOffer(_offerId, code);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(random);
            }
        }
    }

    /// <summary>
    /// Returns a generic match result, not an enrollment secret or authorization.
    /// Host must rate-limit by source and network as well, independently.
    /// </summary>
    internal bool TryMatchCandidate(Guid offerId, string? candidate, TimeSpan monotonicNow)
    {
        lock (_sync)
        {
            if (!StillValid(offerId, monotonicNow) || _awaitingPcApproval)
                return false;

            // All incorrect codes including wrong length count as failures.
            bool shaped = candidate is { Length: 16 } &&
                candidate.All(c => Alphabet.Contains(c));
            byte[] value = shaped ? Encoding.ASCII.GetBytes(candidate!) : [];
            try
            {
                bool match = shaped &&
                    CryptographicOperations.FixedTimeEquals(_codeAscii!, value);
                if (match)
                {
                    _awaitingPcApproval = true;
                    return true; // STILL not paired; local approval required.
                }
            }
            finally
            {
                CryptographicOperations.ZeroMemory(value);
            }

            _failedAttempts++;
            if (_failedAttempts >= 5)
                InvalidateLocked();
            return false;
        }
    }

    /// <summary>
    /// Only a trusted local Windows approval action may invoke confirmation.
    /// Consumes the one-time challenge, including if already expired.
    /// </summary>
    internal bool ConfirmLocally(Guid offerId, TimeSpan monotonicNow)
    {
        lock (_sync)
        {
            if (!StillValid(offerId, monotonicNow) || !_awaitingPcApproval)
                return false;
            InvalidateLocked();
            return true; // Caller may now begin a separately verified enrollment.
        }
    }

    internal void Invalidate()
    {
        lock (_sync) InvalidateLocked();
    }

    private bool StillValid(Guid offerId, TimeSpan monotonicNow)
    {
        if (_disposed || _codeAscii is null || _offerId == Guid.Empty ||
            offerId != _offerId || monotonicNow < _issuedAt ||
            monotonicNow - _issuedAt >= Lifetime)
        {
            // Timeout, rollback, or identity mismatch cannot be treated
            // as a successful grant. Do not revoke a valid offer merely
            // because an unrelated caller supplies a wrong ID.
            if (_codeAscii is not null && offerId == _offerId &&
                (monotonicNow < _issuedAt || monotonicNow - _issuedAt >= Lifetime))
                InvalidateLocked();
            return false;
        }
        return true;
    }

    private void InvalidateLocked()
    {
        if (_codeAscii is not null)
            CryptographicOperations.ZeroMemory(_codeAscii);
        _codeAscii = null;
        _offerId = Guid.Empty;
        _issuedAt = default;
        _failedAttempts = 0;
        _awaitingPcApproval = false;
    }

    private static string EncodeBase32(ReadOnlySpan<byte> bytes)
    {
        // 10 bytes = 80 bits exactly = 16 Base32 symbols. No padding.
        Span<char> chars = stackalloc char[16];
        int bitBuffer = 0;
        int bitsInBuffer = 0;
        int position = 0;
        foreach (byte b in bytes)
        {
            bitBuffer = (bitBuffer << 8) | b;
            bitsInBuffer += 8;
            while (bitsInBuffer >= 5)
            {
                bitsInBuffer -= 5;
                chars[position++] = Alphabet[(bitBuffer >> bitsInBuffer) & 31];
            }
            bitBuffer &= (1 << bitsInBuffer) - 1;
        }
        return new string(chars);
    }

    public void Dispose()
    {
        lock (_sync)
        {
            _disposed = true;
            InvalidateLocked();
        }
    }
}
