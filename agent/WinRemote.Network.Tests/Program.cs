using System.Net.NetworkInformation;
using WinRemote.Network;
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

// Read-only NIC inventory is intentionally never trusted as Private/Firewall proof.
void VerifyInventory(string name, bool condition)
{
    if (!condition) throw new Exception("Inventory failed: " + name);
    Console.WriteLine("PASS inventory " + name);
    passed++;
}

var observed = new WindowsAdapterInventory.ObservedAdapter(
    nic.ToString("D"), NetworkInterfaceType.Wireless80211, OperationalStatus.Up,
    [new WindowsAdapterInventory.ObservedAddress("10.246.73.20", 24)]);
var captured = WindowsAdapterInventory.BuildUnverified([observed]);
VerifyInventory("preserves canonical adapter ID and IPv4",
    captured.Adapters.Count == 1 &&
    captured.Adapters[0].Id == nic &&
    captured.Adapters[0].UnicastIpv4[0].Ipv4 == "10.246.73.20");
VerifyInventory("does not invent Private, firewall or endpoint proof",
    !captured.Adapters[0].IsPrivateProfileVerified &&
    !captured.ScopedFirewallRuleVerified &&
    !captured.ExactEndpointInventoryVerified &&
    !captured.NetworkChangeMonitorActive);
VerifyInventory("OS inventory alone never opens LAN", !Evaluate(request, captured).Allowed);
VerifyInventory("invalid OS adapter ID fails closed",
    WindowsAdapterInventory.BuildUnverified([observed with { Id = "non-guid" }]).Adapters.Count == 0);
VerifyInventory("duplicate adapter GUID fails closed",
    WindowsAdapterInventory.BuildUnverified([observed, observed]).Adapters.Count == 0);
VerifyInventory("duplicate IP on an adapter fails closed",
    WindowsAdapterInventory.BuildUnverified([observed with {
        UnicastIpv4 = [new("10.246.73.20", 24), new("10.246.73.20", 24)]
    }]).Adapters.Count == 0);
VerifyInventory("invalid prefix fails closed",
    WindowsAdapterInventory.BuildUnverified([observed with {
        UnicastIpv4 = [new("10.246.73.20", 33)]
    }]).Adapters.Count == 0);
VerifyInventory("IPv6 literal passed as IPv4 fails closed",
    WindowsAdapterInventory.BuildUnverified([observed with {
        UnicastIpv4 = [new("::1", 24)]
    }]).Adapters.Count == 0);
VerifyInventory("virtual tunnel type is not Ethernet/WiFi",
    !WindowsAdapterInventory.BuildUnverified([observed with {
        InterfaceType = NetworkInterfaceType.Tunnel
    }]).Adapters[0].IsEthernetOrWifi);
VerifyInventory("null snapshot fails closed",
    WindowsAdapterInventory.BuildUnverified(null).Adapters.Count == 0);
var realInventory = WindowsAdapterInventory.CaptureUnverified();
VerifyInventory("live OS inventory cannot mark permission verified",
    !realInventory.ExactEndpointInventoryVerified &&
    !realInventory.ScopedFirewallRuleVerified &&
    !realInventory.NetworkChangeMonitorActive &&
    realInventory.Adapters.All(item => !item.IsPrivateProfileVerified));

// Windows NLM category is a read-only prerequisite, not a Firewall or auth grant.
void ProfileCheck(string name, bool condition)
{
    if (!condition) throw new Exception("Profile failed: " + name);
    Console.WriteLine("PASS profile " + name);
    passed++;
}
const uint expectedProfileIndex = 17;
ProfileCheck("exact matching Private category is observed",
    WindowsNetworkProfileProbe.Parse(expectedProfileIndex,
        "[{\"InterfaceIndex\":17,\"Category\":\"Private\"}]").IsPrivate);
ProfileCheck("Public category is rejected",
    !WindowsNetworkProfileProbe.Parse(expectedProfileIndex,
        "[{\"InterfaceIndex\":17,\"Category\":\"Public\"}]").IsPrivate);
ProfileCheck("DomainAuthenticated is not Private",
    !WindowsNetworkProfileProbe.Parse(expectedProfileIndex,
        "[{\"InterfaceIndex\":17,\"Category\":\"DomainAuthenticated\"}]").IsPrivate);
ProfileCheck("mismatched interface index is rejected",
    !WindowsNetworkProfileProbe.Parse(expectedProfileIndex,
        "[{\"InterfaceIndex\":18,\"Category\":\"Private\"}]").IsPrivate);
ProfileCheck("duplicate profiles rejected",
    !WindowsNetworkProfileProbe.Parse(expectedProfileIndex,
        "[{\"InterfaceIndex\":17,\"Category\":\"Private\"},{\"InterfaceIndex\":17,\"Category\":\"Private\"}]").IsPrivate);
ProfileCheck("no profile rejected",
    !WindowsNetworkProfileProbe.Parse(expectedProfileIndex, "[]").IsPrivate);
ProfileCheck("single-object output rejected instead of accepting ambiguous schema",
    !WindowsNetworkProfileProbe.Parse(expectedProfileIndex,
        "{\"InterfaceIndex\":17,\"Category\":\"Private\"}").IsPrivate);
ProfileCheck("invalid JSON rejected",
    !WindowsNetworkProfileProbe.Parse(expectedProfileIndex, "not-json").IsPrivate);
ProfileCheck("missing category rejected",
    !WindowsNetworkProfileProbe.Parse(expectedProfileIndex,
        "[{\"InterfaceIndex\":17}]").IsPrivate);
ProfileCheck("case-altered category rejected",
    !WindowsNetworkProfileProbe.Parse(expectedProfileIndex,
        "[{\"InterfaceIndex\":17,\"Category\":\"private\"}]").IsPrivate);
ProfileCheck("string interface index rejected",
    !WindowsNetworkProfileProbe.Parse(expectedProfileIndex,
        "[{\"InterfaceIndex\":\"17\",\"Category\":\"Private\"}]").IsPrivate);
ProfileCheck("invalid zero interface index rejected",
    !WindowsNetworkProfileProbe.Parse(0,
        "[{\"InterfaceIndex\":0,\"Category\":\"Private\"}]").IsPrivate);
ProfileCheck("null profile list rejected",
    !WindowsNetworkProfileProbe.Evaluate(expectedProfileIndex, null).IsPrivate);
ProfileCheck("unavailable adapter denied on any OS",
    !WindowsNetworkProfileProbe.ReadForAdapter(Guid.Empty).IsPrivate);
ProfileCheck("profile observation cannot override absent Firewall evidence",
    !Evaluate(request, WindowsAdapterInventory.BuildUnverified([observed])).Allowed);

// ActiveStore firewall rule matching is only a diagnostic, never an approval flag.
void FirewallCheck(string name, bool condition)
{
    if (!condition) throw new Exception("Firewall audit failed: " + name);
    Console.WriteLine("PASS firewall " + name);
    passed++;
}
var expectedFirewall = new WindowsFirewallRuleAudit.ExpectedRule(
    "10.246.73.20", "10.246.73.21", 8443, "Wi-Fi", @"C:\\Program Files\\WinRemote\\agent.exe");
var sampleRule = new {
    Name = "WinRemote.LanOnly", Direction = "Inbound", Enabled = "True",
    Action = "Allow", Profile = "Private", EdgeTraversal = "Block",
    Protocol = "TCP", Program = expectedFirewall.AgentExecutable,
    LocalPort = new[] { "8443" }, LocalAddress = new[] { "10.246.73.20" },
    RemoteAddress = new[] { "10.246.73.21" }, InterfaceAlias = new[] { "Wi-Fi" }
};
string FirewallJson<T>(T value) => System.Text.Json.JsonSerializer.Serialize(new[] { value });
bool Audit<T>(T value) => WindowsFirewallRuleAudit.Parse(expectedFirewall, FirewallJson(value)).ExactRuleShapeObserved;

FirewallCheck("synthetic strict private rule shape observed", Audit(sampleRule));
FirewallCheck("public profile rejected", !Audit(sampleRule with { Profile = "Public" }));
FirewallCheck("public and private profile mix rejected", !Audit(sampleRule with { Profile = "Private, Public" }));
FirewallCheck("unrestricted remote address rejected", !Audit(sampleRule with { RemoteAddress = new[] { "Any" } }));
FirewallCheck("entire subnet rejected", !Audit(sampleRule with { RemoteAddress = new[] { "10.246.73.0/24" } }));
FirewallCheck("multiple remote clients rejected", !Audit(sampleRule with { RemoteAddress = new[] { "10.246.73.21", "10.246.73.22" } }));
FirewallCheck("all local addresses rejected", !Audit(sampleRule with { LocalAddress = new[] { "Any" } }));
FirewallCheck("wrong local port rejected", !Audit(sampleRule with { LocalPort = new[] { "8080" } }));
FirewallCheck("all ports rejected", !Audit(sampleRule with { LocalPort = new[] { "Any" } }));
FirewallCheck("any program rejected", !Audit(sampleRule with { Program = "Any" }));
FirewallCheck("wrong executable rejected", !Audit(sampleRule with { Program = @"C:\\Windows\\System32\\cmd.exe" }));
FirewallCheck("wrong adapter alias rejected", !Audit(sampleRule with { InterfaceAlias = new[] { "Ethernet" } }));
FirewallCheck("any adapter alias rejected", !Audit(sampleRule with { InterfaceAlias = new[] { "Any" } }));
FirewallCheck("edge traversal allowed rejected", !Audit(sampleRule with { EdgeTraversal = "Allow" }));
FirewallCheck("disabled rule rejected", !Audit(sampleRule with { Enabled = "False" }));
FirewallCheck("outbound rule rejected", !Audit(sampleRule with { Direction = "Outbound" }));
FirewallCheck("blocking rule rejected", !Audit(sampleRule with { Action = "Block" }));
FirewallCheck("UDP rule rejected", !Audit(sampleRule with { Protocol = "UDP" }));
FirewallCheck("ambiguous duplicate rule rejected",
    !WindowsFirewallRuleAudit.Parse(expectedFirewall,
        System.Text.Json.JsonSerializer.Serialize(new[] { sampleRule, sampleRule })).ExactRuleShapeObserved);
FirewallCheck("missing rule rejected",
    !WindowsFirewallRuleAudit.Parse(expectedFirewall, "[]").ExactRuleShapeObserved);
FirewallCheck("truncated JSON rejected",
    !WindowsFirewallRuleAudit.Parse(expectedFirewall, "{").ExactRuleShapeObserved);
FirewallCheck("malformed field type rejected",
    !WindowsFirewallRuleAudit.Parse(expectedFirewall,
        FirewallJson(sampleRule with { RemoteAddress = Array.Empty<string>() })).ExactRuleShapeObserved);
FirewallCheck("invalid expected alias rejected",
    !WindowsFirewallRuleAudit.Parse(expectedFirewall with { AdapterAlias = "Any" },
        FirewallJson(sampleRule)).ExactRuleShapeObserved);
FirewallCheck("observed shape cannot override missing OS verification",
    !Evaluate(request, WindowsAdapterInventory.BuildUnverified([observed])).Allowed);

Console.WriteLine($"NetworkBoundaryPolicy: {passed} checks passed (policy + NIC + profile + firewall audit).");
