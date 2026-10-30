using System.Net.NetworkInformation;

namespace WinRemote.Network;

/// <summary>
/// Fail-closed epoch gate for future connections. This is not a listener or an
/// authentication mechanism. Even a valid network epoch is insufficient for access
/// without TLS, authenticated device, request authorization and CSRF protection.
/// </summary>
public sealed class NetworkEpochGuard : IDisposable
{
    public sealed record Lease(long Epoch, CancellationToken Revoked);

    private readonly object _sync = new();
    private CancellationTokenSource? _active;
    private long _epoch;
    private bool _disposed;

    /// <summary>
    /// Internal for now: no app/service may activate this until OS-backed evidence
    /// providers and complete runtime integration have been reviewed.
    /// </summary>
    internal Lease? BeginVerifiedEpoch(
        NetworkBoundaryPolicy.EndpointRequest request,
        NetworkBoundaryPolicy.MachineEvidence evidence)
    {
        lock (_sync)
        {
            if (_disposed ||
                !NetworkBoundaryPolicy.Evaluate(request, evidence).Allowed)
                return null;

            RevokeLocked();
            _active = new CancellationTokenSource();
            return new Lease(_epoch, _active.Token);
        }
    }

    public bool IsActive(Lease? lease)
    {
        lock (_sync)
        {
            return !_disposed && _active is not null && lease is not null &&
                   lease.Epoch == _epoch &&
                   !lease.Revoked.IsCancellationRequested &&
                   lease.Revoked == _active.Token;
        }
    }

    /// <summary>Call whenever NIC, network profile, firewall or endpoint state changes,
    /// becomes unknown, or a monitor fails. Cancellation is immediate; never
    /// reuse an old epoch without complete revalidation.</summary>
    public void Invalidate()
    {
        lock (_sync) RevokeLocked();
    }

    private void RevokeLocked()
    {
        // Guard the epoch against wraparound. This is astronomically unlikely,
        // but an exception should still fail closed rather than leave an active grant.
        if (_epoch == long.MaxValue)
        {
            _disposed = true;
        }
        else
        {
            _epoch++;
        }

        var previous = _active;
        _active = null;
        if (previous is null) return;

        try
        {
            previous.Cancel(throwOnFirstException: false);
        }
        catch (AggregateException)
        {
            // Untrusted subscriber callbacks cannot prevent revocation.
        }
        finally
        {
            previous.Dispose();
        }
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

/// <summary>
/// Windows network-event bridge. Events are invalidation hints, NOT a guarantee
/// of continuous firewall/profile monitoring. A future host must also separately
/// verify effective policies and detect missed changes before granting access.
/// </summary>
public sealed class NetworkEventInvalidator : IDisposable
{
    private readonly NetworkEpochGuard _gate;
    private bool _registered;
    private bool _disposed;

    private NetworkEventInvalidator(NetworkEpochGuard gate) => _gate = gate;

    public static NetworkEventInvalidator? TryRegister(NetworkEpochGuard gate)
    {
        if (gate is null || !OperatingSystem.IsWindows()) return null;
        var invalidator = new NetworkEventInvalidator(gate);
        try
        {
            NetworkChange.NetworkAddressChanged += invalidator.OnAddressChanged;
            NetworkChange.NetworkAvailabilityChanged += invalidator.OnAvailabilityChanged;
            invalidator._registered = true;
            // Registration itself never sets MachineEvidence.NetworkChangeMonitorActive.
            // Invalidate any older epoch due to the unmonitored registration gap.
            gate.Invalidate();
            return invalidator;
        }
        catch (Exception)
        {
            invalidator.Dispose();
            gate.Invalidate();
            return null;
        }
    }

    private void OnAddressChanged(object? sender, EventArgs args) => SignalChange();
    private void OnAvailabilityChanged(object? sender, NetworkAvailabilityEventArgs args) => SignalChange();

    internal void SignalChange()
    {
        // No exception from callbacks must leave network access open.
        try { _gate.Invalidate(); } catch (Exception) { /* gate is already fail-closed */ }
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        if (_registered)
        {
            NetworkChange.NetworkAddressChanged -= OnAddressChanged;
            NetworkChange.NetworkAvailabilityChanged -= OnAvailabilityChanged;
            _registered = false;
        }
        SignalChange();
    }
}
