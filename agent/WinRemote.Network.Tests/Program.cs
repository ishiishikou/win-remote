using static WinRemote.Network.NetworkBoundaryPolicy;

// Synthetic RFC1918 fixture addresses only; do not copy addresses from a home LAN.
var nic = Guid.Parse("550e8400-e29b-41d4-a716-446655440000");
var request = new EndpointRequest(nic, "10.246.73.20", "10.246.73.21", 8443);
var adapter = new AdapterSnapshot(nic, true, true, true,
    [new AddressOnAdapter("10.246.73.20", 24)]);
var evidence = new MachineEvidence(true, true, true, [adapter]);

int passed = 0;
void Check(string name, EndpointRequest? candidate, MachineEvidence? system, bool expected)
{
    var result = Evaluate(candidate, system);
    if (result.Allowed != expected)
        throw new Exception($"{name}: expected Allowed={expected}, got {result.Allowed} ({result.Reason})");
    Console.WriteLine($"PASS {name}: {result.Reason}");
    passed++;
}
void Deny(string name, EndpointRequest candidate, MachineEvidence system)
    => Check(name, candidate, system, false);

Check("valid private Ethernet/WiFi /24 + verified evidence", request, evidence, true);
Check("missing configuration", null, evidence, false);
Check("missing evidence", request, null, false);
Deny("empty adapter id", request with { AdapterId = Guid.Empty }, evidence);
Deny("invalid IPv4 (wildcard)", request with { LocalIpv4 = "0.0.0.0" }, evidence);
Deny("IPv6 literal", request with { LocalIpv4 = "::" }, evidence);
Deny("noncanonical octets", request with { LocalIpv4 = "010.246.073.020" }, evidence);
Deny("shorthand IPv4", request with { LocalIpv4 = "10.246.73" }, evidence);
Deny("public local", request with { LocalIpv4 = "8.8.8.8" }, evidence);
Deny("CGNAT client", request with { ClientIpv4 = "100.64.0.3" }, evidence);
Deny("outside subnet", request with { ClientIpv4 = "10.246.74.21" }, evidence);
Deny("same host", request with { ClientIpv4 = request.LocalIpv4 }, evidence);
Deny("broadcast client", request with { ClientIpv4 = "10.246.73.255" }, evidence);
Deny("network client", request with { ClientIpv4 = "10.246.73.0" }, evidence);
Deny("privileged port", request with { Port = 443 }, evidence);
Deny("nonexistent adapter", request with { AdapterId = Guid.NewGuid() }, evidence);
Deny("duplicate adapter", request, evidence with { Adapters = [adapter, adapter] });
Deny("adapter is down", request, evidence with { Adapters = [adapter with { IsUp = false }] });
Deny("VPN/virtual adapter", request, evidence with { Adapters = [adapter with { IsEthernetOrWifi = false }] });
Deny("public network profile", request, evidence with { Adapters = [adapter with { IsPrivateProfileVerified = false }] });
Deny("missing assigned IPv4", request, evidence with { Adapters = [adapter with { UnicastIpv4 = [] }] });
Deny("ambiguous assigned IPv4", request, evidence with { Adapters = [adapter with {
    UnicastIpv4 = [new AddressOnAdapter(request.LocalIpv4, 24), new AddressOnAdapter(request.LocalIpv4, 24)]
}] });
Deny("unsupported /32", request, evidence with { Adapters = [adapter with {
    UnicastIpv4 = [new AddressOnAdapter(request.LocalIpv4, 32)]
}] });
Deny("firewall not verified", request, evidence with { ScopedFirewallRuleVerified = false });
Deny("endpoint inventory not verified", request, evidence with { ExactEndpointInventoryVerified = false });
Deny("no network change monitor", request, evidence with { NetworkChangeMonitorActive = false });
Check("RFC1918 172.31 range", request with {
    LocalIpv4 = "172.31.10.21", ClientIpv4 = "172.31.10.22"
}, evidence with { Adapters = [adapter with {
    UnicastIpv4 = [new AddressOnAdapter("172.31.10.21", 24)]
}] }, true);
Deny("172.32 is outside RFC1918", request with { LocalIpv4 = "172.32.10.21" }, evidence);

Console.WriteLine($"NetworkBoundaryPolicy: {passed} checks passed (pure logic only).");
