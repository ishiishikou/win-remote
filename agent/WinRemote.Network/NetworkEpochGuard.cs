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
        CancellationTokenSource? prior;
        Lease? lease = null;
        lock (_sync)
        {
            // Failed revalidation MUST invalidate a previously active epoch.
            prior = RevokeLocked();
            if (!_disposed && NetworkBoundaryPolicy.Evaluate(request, evidence).Allowed)
            {
                _active = new CancellationTokenSource();
                lease = new Lease(_epoch, _active.Token);
            }
        }
        CancelAndDispose(prior); // Never run user callbacks under the gate lock.
        return lease;
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

    /// <summary>On any NIC, network profile, firewall or endpoint change,
    /// unknown state or monitoring failure: cancel the active lease and
    /// require fresh complete verification. Never reuse a revoked epoch.</summary>
    public void Invalidate()
    {
        CancellationTokenSource? prior;
        lock (_sync) prior = RevokeLocked();
        CancelAndDispose(prior);
    }

    private CancellationTokenSource? RevokeLocked()
    {
        if (_epoch == long.MaxValue)
            _disposed = true;
        else
            _epoch++;

        var previous = _active;
        _active = null;
        return previous;
    }

    private static void CancelAndDispose(CancellationTokenSource? previous)
    {
        if (previous is null) return;
        try { previous.Cancel(throwOnFirstException: false); }
        catch (AggregateException) { /* callback errors cannot restore access */ }
        finally { previous.Dispose(); }
    }

    public void Dispose()
    {
        CancellationTokenSource? prior;
        lock (_sync)
        {
            _disposed = true;
            prior = RevokeLocked();
        }
        CancelAndDispose(prior);
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
        bool addressHooked = false;
        bool availabilityHooked = false;
        try
        {
            NetworkChange.NetworkAddressChanged += invalidator.OnAddressChanged;
            addressHooked = true;
            NetworkChange.NetworkAvailabilityChanged += invalidator.OnAvailabilityChanged;
            availabilityHooked = true;
            invalidator._registered = true;
            // Registration never establishes complete monitoring evidence.
            gate.Invalidate();
            return invalidator;
        }
        catch (Exception)
        {
            if (addressHooked)
                NetworkChange.NetworkAddressChanged -= invalidator.OnAddressChanged;
            if (availabilityHooked)
                NetworkChange.NetworkAvailabilityChanged -= invalidator.OnAvailabilityChanged;
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
