using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using static WinRemote.Network.NetworkBoundaryPolicy;

namespace WinRemote.Network;

/// <summary>
/// Read-only Windows NIC inventory. This is NOT a verifier of the Windows network
/// profile, effective Firewall policy, endpoint inventory, or continuous monitoring.
/// All such evidence remains FALSE so this result cannot authorize a listener.
/// </summary>
public static class WindowsAdapterInventory
{
    internal sealed record ObservedAddress(string Address, int PrefixLength);
    internal sealed record ObservedAdapter(
        string Id,
        NetworkInterfaceType InterfaceType,
        OperationalStatus Status,
        IReadOnlyList<ObservedAddress>? UnicastIpv4);

    private static MachineEvidence Denied() => new(
        ExactEndpointInventoryVerified: false,
        ScopedFirewallRuleVerified: false,
        NetworkChangeMonitorActive: false,
        Adapters: Array.Empty<AdapterSnapshot>());

    /// <summary>
    /// Query local OS NIC metadata without changing adapter/profile/Firewall settings.
    /// Other platforms and failed/ambiguous OS enumeration produce an empty denial.
    /// Never log discovered addresses without explicit user action.
    /// </summary>
    public static MachineEvidence CaptureUnverified()
    {
        if (!OperatingSystem.IsWindows())
            return Denied();

        try
        {
            var observed = NetworkInterface.GetAllNetworkInterfaces()
                .Select(nic => new ObservedAdapter(
                    nic.Id,
                    nic.NetworkInterfaceType,
                    nic.OperationalStatus,
                    nic.GetIPProperties().UnicastAddresses
                        .Where(address => address.Address.AddressFamily == AddressFamily.InterNetwork)
                        .Select(address => new ObservedAddress(
                            address.Address.ToString(), address.PrefixLength))
                        .ToArray()))
                .ToArray();
            return BuildUnverified(observed);
        }
        catch (Exception)
        {
            // G3 fail-closed: unsupported OS APIs, adapter enumeration failure, etc.
            return Denied();
        }
    }

    // Pure transformation exposed to a friend test assembly, never to the network.
    // Even synthetic perfect fixtures cannot set security evidence flags to TRUE.
    internal static MachineEvidence BuildUnverified(IReadOnlyList<ObservedAdapter>? observations)
    {
        if (observations is null)
            return Denied();

        var result = new List<AdapterSnapshot>();
        var seenIds = new HashSet<Guid>();

        foreach (var nic in observations)
        {
            if (nic is null || !Guid.TryParse(nic.Id, out var adapterId) ||
                adapterId == Guid.Empty || !seenIds.Add(adapterId) ||
                nic.UnicastIpv4 is null)
                return Denied();

            var ipv4 = new List<AddressOnAdapter>();
            var seenAddresses = new HashSet<string>(StringComparer.Ordinal);
            foreach (var entry in nic.UnicastIpv4)
            {
                if (entry is null || entry.PrefixLength is < 0 or > 32 ||
                    !IPAddress.TryParse(entry.Address, out var address) ||
                    address.AddressFamily != AddressFamily.InterNetwork ||
                    !string.Equals(entry.Address, address.ToString(), StringComparison.Ordinal) ||
                    !seenAddresses.Add(entry.Address))
                    return Denied();

                ipv4.Add(new AddressOnAdapter(entry.Address, entry.PrefixLength));
            }

            result.Add(new AdapterSnapshot(
                adapterId,
                nic.Status == OperationalStatus.Up,
                nic.InterfaceType is NetworkInterfaceType.Ethernet or NetworkInterfaceType.Wireless80211,
                IsPrivateProfileVerified: false, // NetworkInterfaceType is not Windows NLM Private evidence.
                UnicastIpv4: ipv4.ToArray()));
        }

        return new MachineEvidence(
            ExactEndpointInventoryVerified: false,
            ScopedFirewallRuleVerified: false,
            NetworkChangeMonitorActive: false,
            Adapters: result.ToArray());
    }
}
