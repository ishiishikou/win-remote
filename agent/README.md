# Windows agent: G3 network-boundary policy (code-only slice)

**Status: pre-listener prototype.** This directory contains a pure .NET 10 network-boundary decision function. It **never** opens TCP/UDP sockets, installs a service, changes the Windows Firewall, issues certificates, or operates Windows remotely.

## Build / run tests (Windows with .NET 10 SDK)

From repository root:

```powershell
dotnet build agent/WinRemote.Network/WinRemote.Network.csproj
dotnet run --project agent/WinRemote.Network.Tests/WinRemote.Network.Tests.csproj
```

No external NuGet packages or cloud services are required for these two projects. The console test harness includes positive/negative cases for allowed local subnet, wildcard/IPv6/public/CGNAT IPs, ambiguous NICs, down/virtual/Public NIC, missing Firewall/endpoint-inventory/monitor evidence, unusable prefix, address collision, and cross-subnet access.

**Verification as of 2026-10-30:** GitHub branch `feat/g3-network-boundary` source files were fetched through the GitHub connector into a dedicated Linux (Alpine 3.24) test directory. After installing .NET 10 SDK 10.0.303 in the test container, `dotnet build agent/WinRemote.Network.Tests/WinRemote.Network.Tests.csproj --configuration Release --nologo --ignore-failed-sources` succeeded with **0 warnings / 0 errors**, and `dotnet run --project agent/WinRemote.Network.Tests/WinRemote.Network.Tests.csproj --configuration Release --no-build` completed with **28 checks passed / exit code 0**. No Windows Home system or Firewall settings were changed. This verifies .NET policy logic on Linux only; **G3 is not passed** without Windows OS evidence and fail-closed runtime integration testing.

After the repository became public, GitHub Actions was restored for push and pull requests using read-only permissions. In [PR run #41090285059](https://github.com/ishiishikou/win-remote/actions/runs/41090285059), both Windows and Ubuntu jobs completed the .NET 10 build and console-check steps successfully. The earlier private-runner startup failures are historical; Windows OS adapter/profile/Firewall integration acceptance **is not verified** by GitHub-hosted CI.

## Read-only Windows NIC inventory (G3-D)

`WindowsAdapterInventory.CaptureUnverified()` uses Windows .NET `NetworkInterface` APIs to read adapter GUIDs, operational status, interface type, and canonical IPv4 unicast addresses/prefix lengths. It **never opens a listener**, modifies a firewall or network profile, or reads secrets. Errors, missing/duplicate adapter IDs, duplicate addresses, malformed IPv4 and invalid prefixes yield a rejected/empty inventory. On non-Windows hosts, the inventory is empty.

The API deliberately returns **false for Windows Private network profile verification, effective Firewall rule verification, additional-endpoint verification and change-monitor state**. A raw `Ethernet`/`Wireless80211` type is not proof the NIC is physical or on a trusted LAN. A future trusted Windows profile/Firewall collector must supply independent evidence; until then, `NetworkBoundaryPolicy.Evaluate()` rejects every collected OS snapshot. No remote caller or config can set those verification flags as a substitute for OS inspection.

The console harness now covers 39 checks (28 boundary-policy + 11 inventory tests). These checks passed on the Linux development container and on the GitHub-hosted Windows/Ubuntu CI; an actual Windows Home/iPhone connected acceptance test is still pending.

## Decision contract

Inputs:

- `EndpointRequest`: selected physical adapter ID, canonical IPv4 address **on that adapter**, registered iPhone IPv4, non-privileged port.
- `MachineEvidence`: single matching up Ethernet/Wi-Fi adapter, Windows `Private` profile verified, exact endpoint inventory, narrowly-scoped **effective** Firewall rule verified, and active change monitor.

The function rejects missing/ambiguous evidence, IPv6 or non-RFC1918 addresses, inconsistent IP prefix, network/broadcast addresses, and cross-subnet client IP. **A successful result is necessary but far from sufficient** to open a listening socket: an app must still enforce HTTPS, bind the one IPv4 (not a wildcard/name), limit effective Firewall remote-address to the registered iPhone's `/32`, authenticate the iPhone, prevent additional IPv6 endpoints, and close all connections on any change.

**Crucially, evidence booleans are not security proof.** They must be populated by trusted Windows OS inspection, not by a web API, remote input, CLI flag, or user-editable YAML. Until collectors exist, use `false` for the evidence and refuse to start. Future Windows collector should reconcile `NetworkInterface.GetAllNetworkInterfaces()` (adapter ID/type/up, IPv4 address/prefix), the Windows Network List Manager / `Get-NetConnectionProfile` (Private profile), and **effective** Firewall filters (`Program`, `InterfaceAlias`, `LocalAddress`, `RemoteAddress=/32`, `Profile=Private`, `Protocol=TCP`, `LocalPort`, edge traversal blocked). Reading a single allow rule alone is not enough. Recheck before listening, on every NIC/profile/Firewall change, and while connected; fail closed when the state cannot be verified.

## Not yet implemented

- Windows Private profile, physical-versus-virtual NIC attestation, effective Firewall evidence providers and OS event monitoring (raw NIC enumeration only is present)
- Kestrel or a service listener; TLS CA storage and HTTPS authentication/CSRF
- Registered-device identity, pairing, expiry/revocation, IP churn handling
- iPhone/Safari/WSS/Windows Home real-device tests
- G1–G9 acceptance criteria and performance comparison

No production listener should consume this class until the OS evidence collector and negative-case integration tests have been completed.

References: [Issue #1](https://github.com/ishiishikou/win-remote/issues/1), [security design](../../docs/design/security.md), [MVP validation](../../docs/design/mvp-validation.md), [Microsoft NetworkInterface](https://learn.microsoft.com/en-us/dotnet/api/system.net.networkinformation.networkinterface?view=net-10.0), [Get-NetConnectionProfile](https://learn.microsoft.com/en-us/powershell/module/netconnection/get-netconnectionprofile), [New-NetFirewallRule](https://learn.microsoft.com/en-us/powershell/module/netsecurity/new-netfirewallrule).
