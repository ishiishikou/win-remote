using System.Diagnostics;
using System.Globalization;
using System.Net.NetworkInformation;
using System.Text.Json;

namespace WinRemote.Network;

/// <summary>
/// Read-only network connection profile probe. A Windows "Private" profile is only
/// one prerequisite; it is never proof of physical LAN, trusted peer, or Firewall.
/// This class deliberately does not populate MachineEvidence approval flags.
/// </summary>
public static class WindowsNetworkProfileProbe
{
    internal sealed record ProfileObservation(uint InterfaceIndex, string Category);

    public sealed record ProbeResult(bool IsPrivate, string Reason)
    {
        public static ProbeResult Deny(string reason) => new(false, reason);
    }

    /// <summary>
    /// Finds exactly one OS adapter by GUID; gets its IPv4 interface index and
    /// reads the corresponding Windows NLM category. No settings are modified.
    /// </summary>
    public static ProbeResult ReadForAdapter(Guid adapterId)
    {
        if (!OperatingSystem.IsWindows())
            return ProbeResult.Deny("unsupported_os");
        if (adapterId == Guid.Empty)
            return ProbeResult.Deny("invalid_adapter_id");

        try
        {
            var adapters = NetworkInterface.GetAllNetworkInterfaces()
                .Where(adapter => Guid.TryParse(adapter.Id, out var id) && id == adapterId)
                .ToArray();
            if (adapters.Length != 1)
                return ProbeResult.Deny("ambiguous_or_missing_adapter");

            var ipv4 = adapters[0].GetIPProperties().GetIPv4Properties();
            if (ipv4 is null || ipv4.Index <= 0)
                return ProbeResult.Deny("missing_ipv4_interface_index");

            return ReadForInterfaceIndex((uint)ipv4.Index);
        }
        catch (Exception)
        {
            return ProbeResult.Deny("adapter_lookup_failed");
        }
    }

    private static ProbeResult ReadForInterfaceIndex(uint index)
    {
        if (index == 0)
            return ProbeResult.Deny("invalid_interface_index");

        var windows = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        if (string.IsNullOrWhiteSpace(windows))
            return ProbeResult.Deny("missing_windows_directory");

        var powershell = Path.Combine(windows, "System32", "WindowsPowerShell", "v1.0", "powershell.exe");
        if (!File.Exists(powershell))
            return ProbeResult.Deny("missing_profile_reader");

        // The only interpolated argument is an OS-supplied unsigned integer.
        // Never accept a script, interface alias, command or path from a remote request.
        var script = "$ErrorActionPreference='Stop';" +
            "$profiles=@(Get-NetConnectionProfile -InterfaceIndex " +
            index.ToString(CultureInfo.InvariantCulture) +
            " -ErrorAction Stop | ForEach-Object {" +
            "[pscustomobject]@{InterfaceIndex=[uint32]$_.InterfaceIndex;Category=[string]$_.NetworkCategory}" +
            "});ConvertTo-Json -InputObject $profiles -Compress -Depth 3";

        var info = new ProcessStartInfo(powershell)
        {
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true
        };
        info.ArgumentList.Add("-NoLogo");
        info.ArgumentList.Add("-NoProfile");
        info.ArgumentList.Add("-NonInteractive");
        info.ArgumentList.Add("-Command");
        info.ArgumentList.Add(script);

        try
        {
            using var process = new Process { StartInfo = info };
            if (!process.Start())
                return ProbeResult.Deny("profile_reader_start_failed");

            var output = process.StandardOutput.ReadToEndAsync();
            var error = process.StandardError.ReadToEndAsync();

            if (!process.WaitForExit(5000))
            {
                process.Kill(entireProcessTree: true);
                return ProbeResult.Deny("profile_reader_timeout");
            }

            if (!Task.WaitAll([output, error], 1000))
                return ProbeResult.Deny("profile_reader_output_timeout");

            if (process.ExitCode != 0 || !string.IsNullOrWhiteSpace(error.Result))
                return ProbeResult.Deny("profile_reader_error");

            return Parse(index, output.Result);
        }
        catch (Exception)
        {
            return ProbeResult.Deny("profile_reader_exception");
        }
    }

    internal static ProbeResult Parse(uint expectedIndex, string? output)
    {
        if (expectedIndex == 0 || string.IsNullOrWhiteSpace(output) || output.Length > 4096)
            return ProbeResult.Deny("invalid_profile_output");
        try
        {
            using var document = JsonDocument.Parse(output);
            if (document.RootElement.ValueKind != JsonValueKind.Array ||
                document.RootElement.GetArrayLength() != 1)
                return ProbeResult.Deny("ambiguous_or_missing_profile");

            var profile = document.RootElement[0];
            if (profile.ValueKind != JsonValueKind.Object ||
                !profile.TryGetProperty("InterfaceIndex", out var index) ||
                !index.TryGetUInt32(out var parsedIndex) ||
                !profile.TryGetProperty("Category", out var category) ||
                category.ValueKind != JsonValueKind.String)
                return ProbeResult.Deny("invalid_profile_shape");

            return Evaluate(expectedIndex, [new ProfileObservation(parsedIndex, category.GetString() ?? "")]);
        }
        catch (Exception)
        {
            return ProbeResult.Deny("invalid_profile_json");
        }
    }

    internal static ProbeResult Evaluate(uint expectedIndex, IReadOnlyList<ProfileObservation>? profiles)
    {
        if (expectedIndex == 0 || profiles is null || profiles.Count != 1 ||
            profiles[0] is null || profiles[0].InterfaceIndex != expectedIndex)
            return ProbeResult.Deny("ambiguous_or_mismatched_profile");

        // Only a literal Private category is eligible even as diagnostic data.
        // Report other known NLM categories without exposing NetworkName/SSID.
        // Unknown or malformed values remain denied and unclassified.
        return profiles[0].Category switch
        {
            "Private" => new ProbeResult(true, "private_profile_observed_only"),
            "Public" => ProbeResult.Deny("public_profile_observed"),
            "DomainAuthenticated" => ProbeResult.Deny("domain_authenticated_profile_observed"),
            _ => ProbeResult.Deny("unknown_or_invalid_profile_category")
        };
    }
}
