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
        "[{\"InterfaceIndex\":17,\"Category\":\"Public\"}]").Reason == "public_profile_observed");
ProfileCheck("DomainAuthenticated emits specific non-identifying denial",
    WindowsNetworkProfileProbe.Parse(expectedProfileIndex,
        "[{\"InterfaceIndex\":17,\"Category\":\"DomainAuthenticated\"}]").Reason == "domain_authenticated_profile_observed");
ProfileCheck("unexpected profile category never grants access",
    !WindowsNetworkProfileProbe.Parse(expectedProfileIndex,
        "[{\"InterfaceIndex\":17,\"Category\":\"Private \"}]").IsPrivate);
ProfileCheck("unexpected profile category uses unknown denial",
    WindowsNetworkProfileProbe.Parse(expectedProfileIndex,
        "[{\"InterfaceIndex\":17,\"Category\":\"Private \"}]").Reason == "unknown_or_invalid_profile_category");

// ActiveStore Private Firewall baseline: an observation is never proof that
// a remote listener is safe to expose. Allow rules can override default block.
void BaselineCheck(string label, bool condition)
{
    if (!condition) throw new Exception("Firewall baseline failed: " + label);
    Console.WriteLine("PASS firewall baseline " + label);
    passed++;
}
var baselineJson = """[{"Name":"Private","Enabled":"True","DefaultInboundAction":"Block","AllowInboundRules":"True"}]""";
bool Baseline(string json) => WindowsFirewallProfileProbe.Parse(json).Observed;
BaselineCheck("canonical blocked inbound profile observed", Baseline(baselineJson));
BaselineCheck("disabled inbound rules still not evidence of full WFP",
    Baseline(baselineJson.Replace("\"AllowInboundRules\":\"True\"", "\"AllowInboundRules\":\"False\"")));
BaselineCheck("wrong public profile rejected",
    !Baseline(baselineJson.Replace("\"Name\":\"Private\"", "\"Name\":\"Public\"")));
BaselineCheck("disabled firewall rejected",
    !Baseline(baselineJson.Replace("\"Enabled\":\"True\"", "\"Enabled\":\"False\"")));
BaselineCheck("open default inbound rejected",
    !Baseline(baselineJson.Replace("\"DefaultInboundAction\":\"Block\"", "\"DefaultInboundAction\":\"Allow\"")));
BaselineCheck("unspecified inbound rejected",
    !Baseline(baselineJson.Replace("\"DefaultInboundAction\":\"Block\"", "\"DefaultInboundAction\":\"NotConfigured\"")));
BaselineCheck("unrecognized rule setting rejected",
    !Baseline(baselineJson.Replace("\"AllowInboundRules\":\"True\"", "\"AllowInboundRules\":\"NotConfigured\"")));
BaselineCheck("missing firewall profile rejected", !Baseline("[]"));
BaselineCheck("duplicate profiles rejected", !Baseline("[" + baselineJson[1..^1] + "," + baselineJson[1..^1] + "]"));
BaselineCheck("object without array rejected", !Baseline(baselineJson[1..^1]));
BaselineCheck("malformed JSON rejected", !Baseline("{"));
BaselineCheck("missing inbound field rejected",
    !Baseline(baselineJson.Replace("\"DefaultInboundAction\":\"Block\",", "")));
BaselineCheck("boolean property type rejected",
    !Baseline(baselineJson.Replace("\"Enabled\":\"True\"", "\"Enabled\":true")));
BaselineCheck("near match of DefaultInboundAction rejected",
    !Baseline(baselineJson.Replace("\"DefaultInboundAction\":\"Block\"", "\"DefaultInboundAction\":\"Block \"")));
BaselineCheck("huge output rejected", !Baseline(new string('A', 4097)));
BaselineCheck("real OS query cannot be misinterpreted as authorization",
    !Evaluate(request, WindowsAdapterInventory.BuildUnverified([observed])).Allowed);

// Coarse ActiveStore allow rule counts are informational only, not proof
// of actual permitted WFP traffic or scoped iPhone access.
void SurveyCheck(string name, bool condition)
{
    if (!condition) throw new Exception("Inbound allow survey failed: " + name);
    Console.WriteLine("PASS inbound survey " + name);
    passed++;
}
const string countsJson = """{"EnabledInboundAllowRules":8,"PrivateApplicableRules":3,"WildcardRemoteRules":1,"UnclassifiedRules":1}""";
var counts = WindowsInboundAllowInventory.Parse(countsJson);
SurveyCheck("consistent non-identifying counts observed",
    counts.Observed && counts.EnabledInboundAllowRules == 8 &&
    counts.PrivateApplicableRules == 3 && counts.WildcardRemoteRules == 1);
SurveyCheck("zero rules is informational, not a grant",
    WindowsInboundAllowInventory.Parse(
        """{"EnabledInboundAllowRules":0,"PrivateApplicableRules":0,"WildcardRemoteRules":0,"UnclassifiedRules":0}""").Observed);
SurveyCheck("missing JSON field denied", !WindowsInboundAllowInventory.Parse(
    countsJson.Replace("\"UnclassifiedRules\":1", "")).Observed);
SurveyCheck("negative count denied", !WindowsInboundAllowInventory.Parse(
    countsJson.Replace("\"EnabledInboundAllowRules\":8", "\"EnabledInboundAllowRules\":-1")).Observed);
SurveyCheck("fractional count denied", !WindowsInboundAllowInventory.Parse(
    countsJson.Replace("\"EnabledInboundAllowRules\":8", "\"EnabledInboundAllowRules\":8.5")).Observed);
SurveyCheck("string count denied", !WindowsInboundAllowInventory.Parse(
    countsJson.Replace("\"EnabledInboundAllowRules\":8", "\"EnabledInboundAllowRules\":\"8\"")).Observed);
SurveyCheck("private count cannot exceed total", !WindowsInboundAllowInventory.Parse(
    countsJson.Replace("\"PrivateApplicableRules\":3", "\"PrivateApplicableRules\":9")).Observed);
SurveyCheck("wildcard cannot exceed private count", !WindowsInboundAllowInventory.Parse(
    countsJson.Replace("\"WildcardRemoteRules\":1", "\"WildcardRemoteRules\":4")).Observed);
SurveyCheck("unknown cannot exceed private count", !WindowsInboundAllowInventory.Parse(
    countsJson.Replace("\"UnclassifiedRules\":1", "\"UnclassifiedRules\":4")).Observed);
SurveyCheck("wildcard plus unknown cannot exceed private count",
    !WindowsInboundAllowInventory.Parse(countsJson
        .Replace("\"WildcardRemoteRules\":1", "\"WildcardRemoteRules\":2")
        .Replace("\"UnclassifiedRules\":1", "\"UnclassifiedRules\":2")).Observed);
SurveyCheck("unexpected array JSON denied", !WindowsInboundAllowInventory.Parse("[" + countsJson + "]").Observed);
SurveyCheck("malformed JSON denied", !WindowsInboundAllowInventory.Parse("{").Observed);
SurveyCheck("oversized JSON denied", !WindowsInboundAllowInventory.Parse(new string('x', 2049)).Observed);
SurveyCheck("no survey can set effective Firewall permission",
    !Evaluate(request, WindowsAdapterInventory.BuildUnverified([observed])).Allowed);

// A valid network epoch alone is NOT sufficient to admit an HTTP request.
// These are synthetic metadata tests, not a deployed HTTP endpoint.
void BrowserCheck(string name, bool expected, BrowserRequestBoundary.Decision result)
{
    if (result.Allowed != expected)
        throw new Exception("HTTP gate " + name + ": " + result.Reason);
    Console.WriteLine("PASS HTTP boundary " + name + ": " + result.Reason);
    passed++;
}
using var browserGate = new NetworkEpochGuard();
var browserLease = browserGate.BeginVerifiedEpoch(request, evidence)!;
var browserEndpoint = new BrowserRequestBoundary.Endpoint("10.246.73.20", 8443);
var browserPost = new BrowserRequestBoundary.Envelope(
    "https", "10.246.73.20:8443", "https://10.246.73.20:8443",
    "POST", "/api/input", "application/json", 256,
    IsWebSocketUpgrade: false, DeviceAuthenticated: true,
    SessionAuthorized: true, CsrfVerified: true,
    OneTimeWebSocketTicketVerified: false);
BrowserRequestBoundary.Decision WebGate(BrowserRequestBoundary.Envelope? envelope,
    BrowserRequestBoundary.Endpoint? endpoint = null,
    NetworkEpochGuard.Lease? lease = null) =>
    BrowserRequestBoundary.Evaluate(endpoint ?? browserEndpoint, envelope, browserGate, lease ?? browserLease);
BrowserCheck("valid synthetic POST envelope", true, WebGate(browserPost));
BrowserCheck("TLS must be established", false,
    WebGate(browserPost with { Scheme = "http" }));
BrowserCheck("Host must be exact", false,
    WebGate(browserPost with { Host = "10.246.73.20" }));
BrowserCheck("wildcard Host not allowed", false,
    WebGate(browserPost with { Host = "0.0.0.0:8443" }));
BrowserCheck("multiple Host headers not allowed", false,
    WebGate(browserPost with { Host = "10.246.73.20:8443,evil:8443" }));
BrowserCheck("user-info Origin not allowed", false,
    WebGate(browserPost with { Origin = "https://user@10.246.73.20:8443" }));
BrowserCheck("cross-site Origin rejected", false,
    WebGate(browserPost with { Origin = "https://10.246.73.21:8443" }));
BrowserCheck("null Origin rejected", false,
    WebGate(browserPost with { Origin = "null" }));
BrowserCheck("missing Origin rejected", false,
    WebGate(browserPost with { Origin = null }));
BrowserCheck("trailing-slash Origin rejected", false,
    WebGate(browserPost with { Origin = "https://10.246.73.20:8443/" }));
BrowserCheck("unauthenticated device rejected", false,
    WebGate(browserPost with { DeviceAuthenticated = false }));
BrowserCheck("expired session rejected", false,
    WebGate(browserPost with { SessionAuthorized = false }));
BrowserCheck("missing CSRF proof rejected", false,
    WebGate(browserPost with { CsrfVerified = false }));
BrowserCheck("GET mutation attempt rejected", false,
    WebGate(browserPost with { Method = "GET" }));
BrowserCheck("arbitrary API route rejected", false,
    WebGate(browserPost with { Path = "/api/admin" }));
BrowserCheck("path normalization rejected", false,
    WebGate(browserPost with { Path = "/api/../input" }));
BrowserCheck("form Content-Type rejected", false,
    WebGate(browserPost with { ContentType = "application/x-www-form-urlencoded" }));
BrowserCheck("mutation 64 KiB limit enforced", false,
    WebGate(browserPost with { BodyByteLength = 65537 }));
BrowserCheck("negative body length rejected", false,
    WebGate(browserPost with { BodyByteLength = -1 }));
BrowserCheck("bounded JSON charset allowed", true,
    WebGate(browserPost with { ContentType = "application/json; charset=utf-8", BodyByteLength = 65536 }));
BrowserCheck("noncanonical local IPv4 endpoint rejected", false,
    WebGate(browserPost, new BrowserRequestBoundary.Endpoint("010.246.073.020", 8443)));
BrowserCheck("privileged port rejected", false,
    WebGate(browserPost, new BrowserRequestBoundary.Endpoint("10.246.73.20", 443)));
var webSocket = browserPost with {
    Method = "GET", Path = "/ws/terminal", ContentType = null,
    BodyByteLength = 0, IsWebSocketUpgrade = true,
    CsrfVerified = false, OneTimeWebSocketTicketVerified = true
};
BrowserCheck("valid synthetic WebSocket envelope", true, WebGate(webSocket));
BrowserCheck("WebSocket missing ticket rejected", false,
    WebGate(webSocket with { OneTimeWebSocketTicketVerified = false }));
BrowserCheck("WebSocket cross-site request rejected", false,
    WebGate(webSocket with { Origin = "https://attacker.invalid" }));
BrowserCheck("WebSocket arbitrary route rejected", false,
    WebGate(webSocket with { Path = "/ws/raw" }));
BrowserCheck("WebSocket with request body rejected", false,
    WebGate(webSocket with { BodyByteLength = 12 }));
BrowserCheck("WebSocket POST attempt rejected", false,
    WebGate(webSocket with { Method = "POST" }));
BrowserCheck("WebSocket unauthenticated device rejected", false,
    WebGate(webSocket with { DeviceAuthenticated = false }));
browserGate.Invalidate();
BrowserCheck("revoked network epoch closes valid POST", false, WebGate(browserPost));
BrowserCheck("revoked network epoch closes valid WSS", false, WebGate(webSocket));
BrowserCheck("null envelope rejected", false, WebGate(null));

// Local Windows-host session time measurements must use a monotonic source.
// A browser-supplied timestamp cannot grant access or extend a session.
void SessionCheck(string name, bool allowed, LocalSessionBoundary.Decision result)
{
    if (result.Allowed != allowed)
        throw new Exception("Session boundary " + name + ": " + result.Reason);
    Console.WriteLine("PASS session " + name + ": " + result.Reason);
    passed++;
}
var normal = new LocalSessionBoundary.MonotonicSnapshot(
    TimeSpan.FromHours(1), TimeSpan.FromMinutes(5),
    SessionRevoked: false, PcLocallyApprovedShell: true,
    PcLocallyApprovedScreen: false,
    PrivilegeWindowAge: TimeSpan.FromMinutes(3),
    ReauthAgeWhenWindowOpened: TimeSpan.FromMinutes(1));
LocalSessionBoundary.Decision Session(LocalSessionBoundary.MonotonicSnapshot? snapshot,
    LocalSessionBoundary.Capability type = LocalSessionBoundary.Capability.Read) =>
    LocalSessionBoundary.Evaluate(snapshot, type);
SessionCheck("normal read allowed within session", true, Session(normal));
SessionCheck("normal input allowed within session", true, Session(normal, LocalSessionBoundary.Capability.Input));
SessionCheck("shell allowed only within explicit PC approval", true, Session(normal, LocalSessionBoundary.Capability.Shell));
SessionCheck("screen not approved by PC denied", false, Session(normal, LocalSessionBoundary.Capability.Screen));
SessionCheck("revoked session denied", false, Session(normal with { SessionRevoked = true }));
SessionCheck("missing session denied", false, Session(null));
SessionCheck("eight hour boundary denied", false,
    Session(normal with { SessionAge = TimeSpan.FromHours(8) }));
SessionCheck("just before eight hours still valid", true,
    Session(normal with { SessionAge = TimeSpan.FromHours(8) - TimeSpan.FromTicks(1) }));
SessionCheck("idle thirty minute boundary denied", false,
    Session(normal with { SinceLastHumanAction = TimeSpan.FromMinutes(30) }));
SessionCheck("idle just before deadline remains valid", true,
    Session(normal with { SinceLastHumanAction = TimeSpan.FromMinutes(30) - TimeSpan.FromTicks(1) }));
SessionCheck("negative session age rejected", false,
    Session(normal with { SessionAge = TimeSpan.FromSeconds(-1) }));
SessionCheck("negative idle age rejected", false,
    Session(normal with { SinceLastHumanAction = TimeSpan.FromSeconds(-1) }));
SessionCheck("idle age greater than session age rejected", false,
    Session(normal with { SinceLastHumanAction = TimeSpan.FromHours(2) }));
SessionCheck("no Shell PC approval denied", false,
    Session(normal with { PcLocallyApprovedShell = false }, LocalSessionBoundary.Capability.Shell));
SessionCheck("Screen approved with window allowed", true,
    Session(normal with { PcLocallyApprovedScreen = true }, LocalSessionBoundary.Capability.Screen));
SessionCheck("missing privilege window denied", false,
    Session(normal with { PrivilegeWindowAge = null }, LocalSessionBoundary.Capability.Shell));
SessionCheck("privileged fifteen-minute limit enforced", false,
    Session(normal with { PrivilegeWindowAge = TimeSpan.FromMinutes(15) }, LocalSessionBoundary.Capability.Shell));
SessionCheck("privileged just before deadline valid", true,
    Session(normal with { PrivilegeWindowAge = TimeSpan.FromMinutes(15) - TimeSpan.FromTicks(1) }, LocalSessionBoundary.Capability.Shell));
SessionCheck("negative privilege age rejected", false,
    Session(normal with { PrivilegeWindowAge = TimeSpan.FromSeconds(-1) }, LocalSessionBoundary.Capability.Shell));
SessionCheck("privilege window beyond session age rejected", false,
    Session(normal with { SessionAge = TimeSpan.FromMinutes(1) }, LocalSessionBoundary.Capability.Shell));
SessionCheck("stale reauth at window opening rejected", false,
    Session(normal with { ReauthAgeWhenWindowOpened = TimeSpan.FromMinutes(6) }, LocalSessionBoundary.Capability.Shell));
SessionCheck("missing reauth evidence rejected", false,
    Session(normal with { ReauthAgeWhenWindowOpened = null }, LocalSessionBoundary.Capability.Shell));
SessionCheck("negative reauth age rejected", false,
    Session(normal with { ReauthAgeWhenWindowOpened = TimeSpan.FromSeconds(-1) }, LocalSessionBoundary.Capability.Shell));
SessionCheck("unknown capability denied", false,
    Session(normal, (LocalSessionBoundary.Capability)99));
SessionCheck("session revoke also denies Shell", false,
    Session(normal with { SessionRevoked = true }, LocalSessionBoundary.Capability.Shell));

Console.WriteLine($"NetworkBoundaryPolicy: {passed} checks passed (policy + NIC + profile + firewall + epoch + auth + baseline + survey + HTTP + session).");
