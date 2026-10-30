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

// Network epoch gate tests. These are synthetic grants; the product does not yet
// possess trusted OS evidence or expose BeginVerifiedEpoch outside the assembly.
void EpochCheck(string name, bool condition)
{
    if (!condition) throw new Exception("Epoch gate failed: " + name);
    Console.WriteLine("PASS epoch " + name);
    passed++;
}
using var epochs = new NetworkEpochGuard();
EpochCheck("default denied", !epochs.IsActive(null));
var first = epochs.BeginVerifiedEpoch(request, evidence);
EpochCheck("valid synthetic verification can arm internal epoch",
    first is not null && epochs.IsActive(first));
EpochCheck("issued lease has revocation token", first!.Revoked.CanBeCanceled);
using var other = new NetworkEpochGuard();
var foreign = other.BeginVerifiedEpoch(request, evidence);
EpochCheck("lease cannot cross guard instances", !epochs.IsActive(foreign));
epochs.Invalidate();
EpochCheck("invalidation instantly disallows prior lease", !epochs.IsActive(first));
EpochCheck("invalidation notifies existing requests", first.Revoked.IsCancellationRequested);
var next = epochs.BeginVerifiedEpoch(request, evidence);
EpochCheck("new verification creates a distinct epoch",
    next is not null && epochs.IsActive(next) && next.Epoch != first.Epoch);
EpochCheck("previous epoch remains invalid", !epochs.IsActive(first));
var badEpoch = epochs.BeginVerifiedEpoch(request,
    evidence with { ScopedFirewallRuleVerified = false });
EpochCheck("failed revalidation cannot grant", badEpoch is null);
EpochCheck("failed revalidation revokes existing permission",
    !epochs.IsActive(next) && next!.Revoked.IsCancellationRequested);
var callbackLease = epochs.BeginVerifiedEpoch(request, evidence)!;
bool callbackReentered = false;
using (callbackLease.Revoked.Register(() => {
    callbackReentered = !epochs.IsActive(callbackLease);
}))
{
    epochs.Invalidate();
}
EpochCheck("revocation callback safely reenters guard", callbackReentered);
epochs.Invalidate();
EpochCheck("repeat invalidation remains denied", !epochs.IsActive(callbackLease));
using var testEvents = NetworkEventInvalidator.TryRegister(epochs);
EpochCheck("event bridge never activates permission", !epochs.IsActive(callbackLease));
var validAfterEvent = epochs.BeginVerifiedEpoch(request, evidence);
testEvents?.SignalChange();
EpochCheck("network event invalidates active lease on Windows",
    testEvents is null || !epochs.IsActive(validAfterEvent));
epochs.Dispose();
EpochCheck("disposed guard denies any earlier or new lease",
    !epochs.IsActive(validAfterEvent) &&
    epochs.BeginVerifiedEpoch(request, evidence) is null);

// Process-memory-only HMAC proof. No local pairing approval UI or HTTPS endpoint exists.
void AuthCheck(string name, bool condition)
{
    if (!condition) throw new Exception("Authentication proof failed: " + name);
    Console.WriteLine("PASS auth " + name);
    passed++;
}
using var auth = new LocalDeviceProofRegistry();
var authNow = DateTimeOffset.FromUnixTimeSeconds(1_800_000_000);
AuthCheck("cannot verify without enrollment",
    !auth.Verify(null, authNow));
AuthCheck("invalid local enrollment lifetime is rejected",
    auth.EnrollLocally(TimeSpan.FromSeconds(1), authNow) is null);
var offer = auth.EnrollLocally(TimeSpan.FromMinutes(10), authNow)!;
AuthCheck("enrollment creates random 256-bit secret",
    offer.SecretHex.Length == 64 && offer.DeviceId != Guid.Empty);
var emptyBodyHash = Convert.ToHexString(
    System.Security.Cryptography.SHA256.HashData(Array.Empty<byte>())).ToLowerInvariant();
LocalDeviceProofRegistry.Proof Sign(
    LocalDeviceProofRegistry.Enrollment enrollment, long when,
    string nonce, string method = "POST", string path = "/api/input",
    string? bodyHash = null)
{
    var p = new LocalDeviceProofRegistry.Proof(enrollment.DeviceId, when,
        nonce, method, path, bodyHash ?? emptyBodyHash, "");
    var hmac = System.Security.Cryptography.HMACSHA256.HashData(
        Convert.FromHexString(enrollment.SecretHex),
        System.Text.Encoding.UTF8.GetBytes(LocalDeviceProofRegistry.SigningMessage(p)));
    return p with { MacHex = Convert.ToHexString(hmac).ToLowerInvariant() };
}
var firstNonce = "0123456789abcdef0123456789abcdef";
var goodProof = Sign(offer, authNow.ToUnixTimeSeconds(), firstNonce);
AuthCheck("correct signed request accepted once", auth.Verify(goodProof, authNow));
AuthCheck("replay of exact request rejected", !auth.Verify(goodProof, authNow));
var pathProof = Sign(offer, authNow.ToUnixTimeSeconds(), "1123456789abcdef0123456789abcdef");
AuthCheck("path mutation fails authentication", !auth.Verify(pathProof with { Path = "/api/files" }, authNow));
AuthCheck("original valid request remains possible after invalid MAC",
    auth.Verify(pathProof, authNow));
var bodyProof = Sign(offer, authNow.ToUnixTimeSeconds(), "2123456789abcdef0123456789abcdef");
AuthCheck("body hash change fails", !auth.Verify(bodyProof with { BodySha256Hex = new string('a', 64) }, authNow));
AuthCheck("method changed without MAC fails", !auth.Verify(bodyProof with { Method = "GET" }, authNow));
AuthCheck("correct signed body accepted", auth.Verify(bodyProof, authNow));
AuthCheck("wrong device rejected",
    !auth.Verify(Sign(offer, authNow.ToUnixTimeSeconds(),
        "3123456789abcdef0123456789abcdef") with { DeviceId = Guid.NewGuid() }, authNow));
AuthCheck("timestamp too old rejected",
    !auth.Verify(Sign(offer, authNow.ToUnixTimeSeconds()-91,
        "4123456789abcdef0123456789abcdef"), authNow));
AuthCheck("timestamp too new rejected",
    !auth.Verify(Sign(offer, authNow.ToUnixTimeSeconds()+91,
        "5123456789abcdef0123456789abcdef"), authNow));
AuthCheck("noncanonical nonce rejected",
    !auth.Verify(Sign(offer, authNow.ToUnixTimeSeconds(),
        "ABCDEF0123456789ABCDEF0123456789"), authNow));
AuthCheck("signed malformed route rejected",
    !auth.Verify(Sign(offer, authNow.ToUnixTimeSeconds(),
        "6123456789abcdef0123456789abcdef", path: "/api/../admin"), authNow));
AuthCheck("forged MAC rejected",
    !auth.Verify(Sign(offer, authNow.ToUnixTimeSeconds(),
        "7123456789abcdef0123456789abcdef") with { MacHex = new string('0', 64) }, authNow));
var oldProof = Sign(offer, authNow.ToUnixTimeSeconds(), "8123456789abcdef0123456789abcdef");
var newOffer = auth.EnrollLocally(TimeSpan.FromMinutes(5), authNow)!;
AuthCheck("re-enrolling revokes old device proof", !auth.Verify(oldProof, authNow));
AuthCheck("new enrollment has a different secret",
    offer.DeviceId != newOffer.DeviceId && offer.SecretHex != newOffer.SecretHex);
var newProof = Sign(newOffer, authNow.ToUnixTimeSeconds(), "9123456789abcdef0123456789abcdef");
AuthCheck("new device proof works", auth.Verify(newProof, authNow));
AuthCheck("expired device proof rejected",
    !auth.Verify(Sign(newOffer, authNow.ToUnixTimeSeconds(),
        "a123456789abcdef0123456789abcdef"), authNow.AddMinutes(6)));
var revokedOffer = auth.EnrollLocally(TimeSpan.FromMinutes(5), authNow)!;
var revokedProof = Sign(revokedOffer, authNow.ToUnixTimeSeconds(), "b123456789abcdef0123456789abcdef");
auth.Revoke();
AuthCheck("manual revocation invalidates pending proof", !auth.Verify(revokedProof, authNow));
auth.Dispose();
AuthCheck("disposed registry cannot enroll again",
    auth.EnrollLocally(TimeSpan.FromMinutes(5), authNow) is null);

ProfileCheck("Public category emits specific non-identifying denial",
    WindowsNetworkProfileProbe.Parse(expectedProfileIndex,
        "[{\\"InterfaceIndex\\":17,\\"Category\\":\\"Public\\"}]").Reason == "public_profile_observed");
ProfileCheck("DomainAuthenticated emits specific non-identifying denial",
    WindowsNetworkProfileProbe.Parse(expectedProfileIndex,
        "[{\\"InterfaceIndex\\":17,\\"Category\\":\\"DomainAuthenticated\\"}]").Reason == "domain_authenticated_profile_observed");
ProfileCheck("unexpected profile category never grants access",
    !WindowsNetworkProfileProbe.Parse(expectedProfileIndex,
        "[{\\"InterfaceIndex\\":17,\\"Category\\":\\"Private \\"}]").IsPrivate);
ProfileCheck("unexpected profile category uses unknown denial",
    WindowsNetworkProfileProbe.Parse(expectedProfileIndex,
        "[{\\"InterfaceIndex\\":17,\\"Category\\":\\"Private \\"}]").Reason == "unknown_or_invalid_profile_category");

Console.WriteLine($"NetworkBoundaryPolicy: {passed} checks passed (policy + NIC + profile + firewall + epoch + auth).");
