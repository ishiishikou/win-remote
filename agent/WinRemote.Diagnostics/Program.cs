using WinRemote.Network;

if (args.Length == 0 || args[0] != "--local-diagnostic" ||
    (args.Length > 2 || (args.Length == 2 && args[1] != "--details")))
{
    Console.WriteLine("Read-only local Windows diagnostics.");
    Console.WriteLine("Usage: WinRemote.Diagnostics --local-diagnostic [--details]");
    Console.WriteLine("Default output omits adapter GUID, IPv4, Wi-Fi SSID and machine identifiers.");
    Console.WriteLine("Do not use this utility as proof that LAN access is safe.");
    return 2;
}

if (!OperatingSystem.IsWindows())
{
    Console.WriteLine("G3_READY=false");
    Console.WriteLine("reason=unsupported_platform");
    return 3;
}

bool details = args.Length == 2;
var evidence = WindowsAdapterInventory.CaptureUnverified();
var candidates = evidence.Adapters
    .Where(x => x.IsUp && x.IsEthernetOrWifi && x.UnicastIpv4.Count > 0)
    .OrderBy(x => x.Id)
    .Take(16)
    .ToArray();

Console.WriteLine("G3_READY=false"); // Never emit true: Firewall/auth/monitor are not verified.
Console.WriteLine("mode=read_only");
Console.WriteLine("local_adapter_count=" + evidence.Adapters.Count);
Console.WriteLine("potential_lan_adapters=" + candidates.Length);
Console.WriteLine("network_listener_started=false");
Console.WriteLine("firewall_modified=false");
Console.WriteLine("certificate_store_modified=false");

int privateObserved = 0;
for (int i = 0; i < candidates.Length; i++)
{
    var adapter = candidates[i];
    var profile = WindowsNetworkProfileProbe.ReadForAdapter(adapter.Id);
    if (profile.IsPrivate) privateObserved++;
    Console.WriteLine("adapter_" + (i + 1) + "_private_observed=" +
        (profile.IsPrivate ? "true" : "false"));
    Console.WriteLine("adapter_" + (i + 1) + "_profile_reason=" + profile.Reason);

    if (details)
    {
        Console.WriteLine("adapter_" + (i + 1) + "_guid=" + adapter.Id);
        Console.WriteLine("adapter_" + (i + 1) + "_ipv4=" +
            string.Join(",", adapter.UnicastIpv4.Select(ip => ip.Ipv4 + "/" + ip.PrefixLength)));
    }
}
Console.WriteLine("private_profiles_observed=" + privateObserved);
// Diagnostic observation only: an enabled firewall with default inbound
// Block may still have wide allow rules or third-party filtering.
var firewallBaseline = WindowsFirewallProfileProbe.ReadPrivateBaseline();
Console.WriteLine("private_firewall_baseline_observed=" +
    (firewallBaseline.Observed ? "true" : "false"));
Console.WriteLine("private_firewall_baseline_reason=" + firewallBaseline.Reason);
Console.WriteLine("effective_firewall_verified=false");
Console.WriteLine("continuous_monitor_verified=false");
Console.WriteLine("device_authentication_verified=false");
Console.WriteLine("WARNING=This is diagnostics only. Do not open LAN ports.");
if (details)
    Console.WriteLine("WARNING=Detailed output may identify your LAN; do not post it publicly.");
return 0;
