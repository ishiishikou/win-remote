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

## Read-only Windows network category probe (G3-E)

`WindowsNetworkProfileProbe.ReadForAdapter(Guid)` maps an OS-enumerated NIC GUID to its IPv4 InterfaceIndex and invokes Windows PowerShell's **read-only** `Get-NetConnectionProfile -InterfaceIndex` to query the current network category. The subprocess uses the Windows system PowerShell executable with `-NoProfile`, `-NonInteractive`, a fixed command template, a numeric OS-supplied index, a five-second timeout and strict JSON parsing. It does not use `Set-NetConnectionProfile`, change a Firewall rule, install anything, or listen on a port. It does not print adapter names, SSIDs or addresses.

Only one exact matching `Private` category is reported as observed; `Public`, `DomainAuthenticated`, missing/duplicate/mismatched categories, malformed output, subprocess errors, timeouts and non-Windows platforms all fail closed. A category observation is a **diagnostic prerequisite, not an authorization grant**: this probe does **not** set `IsPrivateProfileVerified` on `MachineEvidence`, does not prove the NIC is physically trusted, and cannot enable a LAN listener. Effective Windows Firewall verification, endpoint inventory, event monitoring and device authentication remain independent unimplemented requirements.

15 negative/positive cases cover category matching, type/schema checking, and rejection of missing/ambiguous evidence. The test harness now has **54 checks** (28 network policy, 11 NIC inventory, 15 network profile). Linux pure-logic execution and GitHub-hosted Windows/Ubuntu CI passed for commit `6e9c4904dcae43ff2c3ce9b180e6a64cd0726df7`. The synthetic category parsing was validated on Windows CI, but a real Windows Home `Get-NetConnectionProfile` read and physical adapter selection have **not** been validated.

Documentation: [Get-NetConnectionProfile](https://learn.microsoft.com/en-us/powershell/module/netconnection/get-netconnectionprofile).

## Windows Firewall ActiveStore shape audit (G3-F)

`WindowsFirewallRuleAudit.Inspect(expected)` is **read-only**. On Windows it inspects the fixed named rule `WinRemote.LanOnly` from `Get-NetFirewallRule -PolicyStore ActiveStore` and its separate port, address, program and interface filters, using a fixed PowerShell query. The scope parser rejects non-Private/inbound/allow/active rules, wrong executable/interface, wildcard ports and addresses, subnet-wide remote access, non-TCP protocols, edge traversal, duplicates, missing rule and invalid response shapes. A successful inspection returns the reason `single_rule_shape_observed_not_effective_policy`.

**This is diagnostic only.** It does *not* establish the complete effective Windows Filtering Platform policy (including other allow rules, policy conflicts, IPv6, third-party filtering and future changes), and it **never sets `ScopedFirewallRuleVerified` to true**. There is still no firewall rule installer or listener. Additional verified OS evidence and negative tests must exist before any real connection can be accepted.

24 firewall audit cases were added, bringing the pure policy + NIC + profile + firewall diagnostic checks to **78**. They passed in the Linux test container using .NET 10. Windows GitHub-hosted runner results are separately tracked in [Issue #1](https://github.com/ishiishikou/win-remote/issues/1); the home Windows machine has not been inspected.

Microsoft documentation: [Get-NetFirewallRule](https://learn.microsoft.com/en-us/powershell/module/netsecurity/get-netfirewallrule), [Get-NetFirewallPortFilter](https://learn.microsoft.com/en-us/powershell/module/netsecurity/get-netfirewallportfilter), [Get-NetFirewallAddressFilter](https://learn.microsoft.com/en-us/powershell/module/netsecurity/get-netfirewalladdressfilter).

## Revocable network epoch guard (G3-G)

`NetworkEpochGuard` defaults to denied and has **no public activation method**. Its assembly-internal `BeginVerifiedEpoch` requires a passing `NetworkBoundaryPolicy` evaluation; failed revalidation revokes existing leases. Every invalidation increments a generation and cancels previously issued `CancellationToken` leases. Callback cancellation takes place outside the internal lock so a callback cannot deadlock by reentering the guard. Disposing a guard prevents future activation.

`NetworkEventInvalidator` subscribes to Windows network address and availability change notifications and immediately invalidates the active epoch. Registration failure, deregistration, unknown state, and event handling all err toward closing access. **Events are only invalidation hints**; they can miss Firewall/profile changes, so they never set `MachineEvidence.NetworkChangeMonitorActive` or claim continuous protection. An eventual host must also poll verified OS state and abort all sockets/requests on invalidation. A revoked lease cannot be reused.

15 epoch/cancellation checks added, bringing the test harness to **93 checks**. These are logic checks; no network listener, live Firewall enforcement, pairing or Windows Home device tests are present.

## In-memory single-device HMAC proof (G3-H)

`LocalDeviceProofRegistry` is **not a network-facing pairing endpoint**. It issues one random 256-bit device secret only through an **assembly-internal** enrollment method, for a future physically approved local Windows-user interface. The key exists only in process memory, is zeroed on revocation/disposal, cannot survive a restart, and is never logged. A new enrollment replaces the old device. The experimental maximum lifetime is 24 hours; the local UI, protection of the pairing secret and durable key storage are **not** implemented.

Request proofs bind a 128-bit one-time nonce, device ID, time, method (GET/POST), exact API path and SHA-256 body hash using HMAC-SHA256. Verification enforces a 90-second clock-skew limit, strict canonical input shapes, fixed-time MAC comparison, a bounded replay set (fail closed when full), expiry, and explicit revocation. **A future HTTP layer must independently calculate the body hash from the actual bytes, authenticate the TLS client endpoint, enforce Host/Origin/CSRF and never permit remote enrollment.** Possession of the secret alone is not a completed end-to-end security system.

22 negative/positive proof checks were added, bringing the test harness to **115 checks**. They passed on an isolated .NET 10 Linux runtime and in GitHub-hosted Windows/Ubuntu CI for commit `b3a8a58921f03b607b8495c9592ff6209af03347`. No iPhone pairing, browser authentication, physical user approval or LAN listener has been implemented.

## Non-admin Windows Home diagnostic (G3-I)

`agent/WinRemote.Diagnostics` is a **read-only** console app. It enumerates adapters and checks their currently observed Windows Private network category, but prints `G3_READY=false` unconditionally because effective Firewall, trusted physical NIC, continuous monitor and authentication gates are **not** verified. It does not open a port, change Windows Firewall, install a service, create a certificate, or register a device.

After downloading source and installing .NET 10 SDK, run from a local Windows terminal **without elevation**:

```powershell
dotnet run --project agent/WinRemote.Diagnostics/WinRemote.Diagnostics.csproj -- --local-diagnostic
```

The default output contains only counts, per-index Private-profile observations and denial reasons; it omits the IPv4 addresses, adapter GUIDs, SSIDs and device name. Optional `--details` prints local adapter GUIDs and IPv4 addresses **only to the local console**; do not put detailed output in a public issue or PR. `G3_READY=false` is expected on a healthy computer until the remaining production gates have been built and tested.

A self-contained Windows x64 artifact can be built on GitHub Actions by `.github/workflows/windows-diagnostic-package.yml`. The Actions artifact includes an unsigned `WinRemote.Diagnostics.exe` and `SHA256.txt` and is retained for only seven days. This is an optional **inspection tool, not the final app or an installer**. Verify its run's SHA and provenance; never blindly override SmartScreen or execute an unexpected binary. The GitHub-hosted Windows runner smoke test checks the read-only code path, not your home PC, and does not prove the Agent is safe to expose.

## Windows Home field observation: non-Private network profile

A Windows Home user executed the standalone **read-only** diagnostic on 2026-10-31 JST. It reported `local_adapter_count=47`, `potential_lan_adapters=1`, and `adapter_1_private_observed=false / adapter_1_profile_reason=not_private`. No listener, Firewall modification or certificate-store modification was reported. The total adapter count includes virtual/non-candidate adapters; it does not imply 47 actual LAN links. `G3_READY=false` is intentionally printed even on a trusted machine while the other security gates are absent.

The original `not_private` reason did **not** distinguish Public, DomainAuthenticated or unrecognized profile categories. The profile probe now reports separate, non-identifying reasons: `public_profile_observed`, `domain_authenticated_profile_observed`, and `unknown_or_invalid_profile_category`. This preserves denial for every non-Private category and never prints the network name or SSID. The previously downloaded executable is unchanged; the new code is only on the development branch until repackaged.

Before considering any Windows network-profile change, the owner can safely run the following **read-only** command in an ordinary local PowerShell terminal:

```powershell
Get-NetConnectionProfile | Select-Object InterfaceAlias, InterfaceIndex, NetworkCategory, IPv4Connectivity | Format-Table -AutoSize
```

Confirm which entry corresponds to the intended, personally trusted home Wi-Fi/Ethernet. Do not switch a guest, workplace or public network to Private merely to satisfy a diagnostic. **Do not run `Set-NetConnectionProfile` automatically**; any profile change needs an informed user decision. Even observing Private does not establish Firewall, TLS or device authentication safety.

## Home Windows Private profile verified (G3 field evidence)

On 2026-10-31 JST, the owner changed the intended home Wi-Fi (InterfaceIndex 9) to `Private` in Windows Settings. The read-only `Get-NetConnectionProfile` query confirmed `Wi-Fi / Private`, and the standalone diagnostic reported `potential_lan_adapters=1`, `adapter_1_private_observed=true`, `adapter_1_profile_reason=private_profile_observed_only` and `private_profiles_observed=1`. No listener was started or Firewall/certificate configuration was modified by the diagnostic. **This establishes the selected Home PC's Private-profile observation, not G3 authorization.** The profile can change later; a production host must recheck it continuously.

## Windows Firewall ActiveStore Private baseline (G3-K)

`WindowsFirewallProfileProbe.ReadPrivateBaseline()` performs a **read-only**, fixed-command query via `Get-NetFirewallProfile -PolicyStore ActiveStore -Name Private`. It checks a single well-formed Private profile, firewall enabled, inbound default Block, and an explicitly configured inbound-rule setting. Invalid/missing/duplicate/unexpected responses fail closed. The default diagnostic CLI now reports `private_firewall_baseline_observed` and a non-identifying reason without printing individual Windows Firewall rules or machine identifiers.

**A baseline observation is not an effective Firewall policy audit**: per-program/port allow rules, IPv6, third-party WFP filters, interface scoping, and dynamic policy changes are not established. The CLI still prints `effective_firewall_verified=false` and `G3_READY=false` in all cases; this probe never populates `MachineEvidence.ScopedFirewallRuleVerified`. Additional packet-path and local-rule scope verification must precede any LAN listener.

A safe non-administrator local check using built-in PowerShell is:

```powershell
Get-NetFirewallProfile -PolicyStore ActiveStore -Name Private | Select-Object Name, Enabled, DefaultInboundAction, AllowInboundRules | Format-Table -AutoSize
```

Do **not** run `Set-NetFirewallProfile`, `New-NetFirewallRule`, or port-opening commands as part of this check. See [Microsoft documentation](https://learn.microsoft.com/en-us/powershell/module/netsecurity/get-netfirewallprofile) for `ActiveStore` semantics. The .NET console harness now contains **135 checks** (119 prior checks plus 16 new Firewall baseline checks), passing in Linux .NET10 and GitHub-hosted Windows/Ubuntu CI.

## Decision contract

Inputs:

- `EndpointRequest`: selected physical adapter ID, canonical IPv4 address **on that adapter**, registered iPhone IPv4, non-privileged port.
- `MachineEvidence`: single matching up Ethernet/Wi-Fi adapter, Windows `Private` profile verified, exact endpoint inventory, narrowly-scoped **effective** Firewall rule verified, and active change monitor.

The function rejects missing/ambiguous evidence, IPv6 or non-RFC1918 addresses, inconsistent IP prefix, network/broadcast addresses, and cross-subnet client IP. **A successful result is necessary but far from sufficient** to open a listening socket: an app must still enforce HTTPS, bind the one IPv4 (not a wildcard/name), limit effective Firewall remote-address to the registered iPhone's `/32`, authenticate the iPhone, prevent additional IPv6 endpoints, and close all connections on any change.

**Crucially, evidence booleans are not security proof.** They must be populated by trusted Windows OS inspection, not by a web API, remote input, CLI flag, or user-editable YAML. Until collectors exist, use `false` for the evidence and refuse to start. Future Windows collector should reconcile `NetworkInterface.GetAllNetworkInterfaces()` (adapter ID/type/up, IPv4 address/prefix), the Windows Network List Manager / `Get-NetConnectionProfile` (Private profile), and **effective** Firewall filters (`Program`, `InterfaceAlias`, `LocalAddress`, `RemoteAddress=/32`, `Profile=Private`, `Protocol=TCP`, `LocalPort`, edge traversal blocked). Reading a single allow rule alone is not enough. Recheck before listening, on every NIC/profile/Firewall change, and while connected; fail closed when the state cannot be verified.

## Not yet implemented

- Trusted Windows Private profile-to-adapter attestation, physical-versus-virtual NIC attestation, effective Firewall evidence providers and OS event monitoring (read-only NIC enumeration and separate profile category observation are present; neither authorizes access)
- Kestrel or a service listener; TLS CA storage and HTTPS authentication/CSRF
- Registered-device identity, pairing, expiry/revocation, IP churn handling
- iPhone/Safari/WSS/Windows Home real-device tests
- G1–G9 acceptance criteria and performance comparison

No production listener should consume this class until the OS evidence collector and negative-case integration tests have been completed.

References: [Issue #1](https://github.com/ishiishikou/win-remote/issues/1), [security design](../../docs/design/security.md), [MVP validation](../../docs/design/mvp-validation.md), [Microsoft NetworkInterface](https://learn.microsoft.com/en-us/dotnet/api/system.net.networkinformation.networkinterface?view=net-10.0), [Get-NetConnectionProfile](https://learn.microsoft.com/en-us/powershell/module/netconnection/get-netconnectionprofile), [New-NetFirewallRule](https://learn.microsoft.com/en-us/powershell/module/netsecurity/new-netfirewallrule).
