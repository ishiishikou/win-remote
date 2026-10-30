# Windows agent: G3 network-boundary policy (code-only slice)

**Status: pre-listener prototype.** This directory contains a pure .NET 10 network-boundary decision function. It **never** opens TCP/UDP sockets, installs a service, changes the Windows Firewall, issues certificates, or operates Windows remotely.

## Build / run tests (Windows with .NET 10 SDK)

From repository root:

```powershell
dotnet build agent/WinRemote.Network/WinRemote.Network.csproj
dotnet run --project agent/WinRemote.Network.Tests/WinRemote.Network.Tests.csproj
```

No external NuGet packages or cloud services are required for these two projects. The console test harness includes positive/negative cases for allowed local subnet, wildcard/IPv6/public/CGNAT IPs, ambiguous NICs, down/virtual/Public NIC, missing Firewall/endpoint-inventory/monitor evidence, unusable prefix, address collision, and cross-subnet access.

**Verification as of 2026-10-30:** source files added and inspected. The current execution environment has no .NET SDK, so **build and console tests have not been executed**. Do not mark G3 passed. Actual Windows Home testing remains necessary.

## Decision contract

Inputs:

- `EndpointRequest`: selected physical adapter ID, canonical IPv4 address **on that adapter**, registered iPhone IPv4, non-privileged port.
- `MachineEvidence`: single matching up Ethernet/Wi-Fi adapter, Windows `Private` profile verified, exact endpoint inventory, narrowly-scoped **effective** Firewall rule verified, and active change monitor.

The function rejects missing/ambiguous evidence, IPv6 or non-RFC1918 addresses, inconsistent IP prefix, network/broadcast addresses, and cross-subnet client IP. **A successful result is necessary but far from sufficient** to open a listening socket: an app must still enforce HTTPS, bind the one IPv4 (not a wildcard/name), limit effective Firewall remote-address to the registered iPhone's `/32`, authenticate the iPhone, prevent additional IPv6 endpoints, and close all connections on any change.

**Crucially, evidence booleans are not security proof.** They must be populated by trusted Windows OS inspection, not by a web API, remote input, CLI flag, or user-editable YAML. Until collectors exist, use `false` for the evidence and refuse to start. Future Windows collector should reconcile `NetworkInterface.GetAllNetworkInterfaces()` (adapter ID/type/up, IPv4 address/prefix), the Windows Network List Manager / `Get-NetConnectionProfile` (Private profile), and **effective** Firewall filters (`Program`, `InterfaceAlias`, `LocalAddress`, `RemoteAddress=/32`, `Profile=Private`, `Protocol=TCP`, `LocalPort`, edge traversal blocked). Reading a single allow rule alone is not enough. Recheck before listening, on every NIC/profile/Firewall change, and while connected; fail closed when the state cannot be verified.

## Not yet implemented

- Trusted Windows adapters/profile/Firewall evidence providers and OS event monitoring
- Kestrel or a service listener; TLS CA storage and HTTPS authentication/CSRF
- Registered-device identity, pairing, expiry/revocation, IP churn handling
- iPhone/Safari/WSS/Windows Home real-device tests
- G1–G9 acceptance criteria and performance comparison

No production listener should consume this class until the OS evidence collector and negative-case integration tests have been completed.

References: [Issue #1](https://github.com/ishiishikou/win-remote/issues/1), [security design](../../docs/design/security.md), [MVP validation](../../docs/design/mvp-validation.md), [Microsoft NetworkInterface](https://learn.microsoft.com/en-us/dotnet/api/system.net.networkinformation.networkinterface?view=net-10.0), [Get-NetConnectionProfile](https://learn.microsoft.com/en-us/powershell/module/netconnection/get-netconnectionprofile), [New-NetFirewallRule](https://learn.microsoft.com/en-us/powershell/module/netsecurity/new-netfirewallrule).
