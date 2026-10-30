using System.Globalization;
using System.Net;

namespace WinRemote.Network;

/// <summary>
/// Evaluation-only guard for a future Windows Home agent. This code never opens sockets,
/// changes Firewall rules, changes adapter settings, or trusts IP/MAC as authentication.
/// </summary>
public static class NetworkBoundaryPolicy
{
    public sealed record EndpointRequest(Guid AdapterId, string LocalIpv4, string ClientIpv4, int Port);

    public sealed record AddressOnAdapter(string Ipv4, int PrefixLength);

    public sealed record AdapterSnapshot(
        Guid Id,
        bool IsUp,
        bool IsEthernetOrWifi,
        bool IsPrivateProfileVerified,
        IReadOnlyList<AddressOnAdapter> UnicastIpv4);

    /// <summary>
    /// Evidence flags must be supplied by trusted Windows OS inspection, NEVER by a
    /// web request or user-editable config. Until all evidence providers are implemented,
    /// pass false and reject start. In particular, the Firewall verification must check
    /// the effective rule, not merely the existence of an Allow rule.
    /// </summary>
    public sealed record MachineEvidence(
        bool ExactEndpointInventoryVerified,
        bool ScopedFirewallRuleVerified,
        bool NetworkChangeMonitorActive,
        IReadOnlyList<AdapterSnapshot> Adapters);

    public sealed record Decision(bool Allowed, string Reason)
    {
        public static Decision Deny(string reason) => new(false, reason);
        public static Decision Permit() => new(true, "allowed");
    }

    public static Decision Evaluate(EndpointRequest? request, MachineEvidence? machine)
    {
        if (request is null || machine is null)
            return Decision.Deny("missing_evidence");

        if (request.AdapterId == Guid.Empty)
            return Decision.Deny("invalid_adapter_id");

        if (!TryParseCanonicalIpv4(request.LocalIpv4, out var local) ||
            !TryParseCanonicalIpv4(request.ClientIpv4, out var client))
            return Decision.Deny("invalid_ipv4");

        if (request.Port < 1024 || request.Port > 65535)
            return Decision.Deny("invalid_port");

        if (!IsRfc1918(local) || !IsRfc1918(client))
            return Decision.Deny("non_private_address");

        if (!machine.ExactEndpointInventoryVerified ||
            !machine.ScopedFirewallRuleVerified ||
            !machine.NetworkChangeMonitorActive)
            return Decision.Deny("system_evidence_incomplete");

        if (machine.Adapters is null)
            return Decision.Deny("missing_adapters");

        var adapters = machine.Adapters
            .Where(adapter => adapter is not null && adapter.Id == request.AdapterId)
            .ToArray();
        if (adapters.Length != 1)
            return Decision.Deny("ambiguous_or_missing_adapter");

        var selected = adapters[0];
        if (!selected.IsUp || !selected.IsEthernetOrWifi || !selected.IsPrivateProfileVerified)
            return Decision.Deny("untrusted_adapter");

        if (selected.UnicastIpv4 is null)
            return Decision.Deny("missing_unicast_addresses");

        var addresses = selected.UnicastIpv4
            .Where(address => address is not null &&
                TryParseCanonicalIpv4(address.Ipv4, out var assigned) && assigned.Equals(local))
            .ToArray();
        if (addresses.Length != 1)
            return Decision.Deny("ambiguous_or_missing_local_ip");

        int prefix = addresses[0].PrefixLength;
        // /31 and /32 have no usable ordinary host pair for this MVP.
        if (prefix < 8 || prefix > 30)
            return Decision.Deny("unsupported_prefix");

        uint mask = uint.MaxValue << (32 - prefix);
        uint localValue = ToUInt32(local);
        uint clientValue = ToUInt32(client);
        uint network = localValue & mask;
        uint broadcast = network | ~mask;

        if (localValue == network || localValue == broadcast ||
            clientValue == network || clientValue == broadcast)
            return Decision.Deny("network_or_broadcast_address");

        if (clientValue == localValue || (clientValue & mask) != network)
            return Decision.Deny("client_not_on_selected_subnet");

        // The caller MUST still bind only request.LocalIpv4, install the /32 client
        // Firewall restriction, authenticate the registered device, and continuously
        // re-evaluate when NIC/profile/firewall state changes.
        return Decision.Permit();
    }

    private static bool TryParseCanonicalIpv4(string? input, out IPAddress ip)
    {
        ip = IPAddress.None;
        if (string.IsNullOrWhiteSpace(input))
            return false;

        var parts = input.Split('.');
        if (parts.Length != 4)
            return false;

        var octets = new byte[4];
        for (int i = 0; i < 4; i++)
        {
            if (parts[i].Length == 0 || parts[i].Length > 3 ||
                (parts[i].Length > 1 && parts[i][0] == '0') ||
                !byte.TryParse(parts[i], NumberStyles.None, CultureInfo.InvariantCulture, out octets[i]))
                return false;
        }
        ip = new IPAddress(octets);
        return true;
    }

    private static bool IsRfc1918(IPAddress ip)
    {
        var b = ip.GetAddressBytes();
        return b.Length == 4 &&
               (b[0] == 10 ||
                (b[0] == 172 && b[1] >= 16 && b[1] <= 31) ||
                (b[0] == 192 && b[1] == 168));
    }

    private static uint ToUInt32(IPAddress ip)
    {
        var b = ip.GetAddressBytes();
        return ((uint)b[0] << 24) | ((uint)b[1] << 16) |
               ((uint)b[2] << 8) | b[3];
    }
}
