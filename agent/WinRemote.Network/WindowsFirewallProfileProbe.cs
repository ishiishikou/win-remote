using System.Diagnostics;
using System.Text.Json;

namespace WinRemote.Network;

/// <summary>
/// Read-only Windows Firewall Private profile baseline observation. Not a proof
/// of effective WFP/allow-rule behavior and never an authorization grant.
/// </summary>
public static class WindowsFirewallProfileProbe
{
    public sealed record BaselineObservation(bool Observed, string Reason)
    {
        public static BaselineObservation Deny(string reason) => new(false, reason);
    }

    /// <summary>
    /// Reads the resulting ActiveStore Private profile, without elevation or
    /// changing its settings. Does not print policy details or machine identity.
    /// </summary>
    public static BaselineObservation ReadPrivateBaseline()
    {
        if (!OperatingSystem.IsWindows())
            return BaselineObservation.Deny("unsupported_os");

        var windows = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        if (string.IsNullOrWhiteSpace(windows))
            return BaselineObservation.Deny("missing_windows_directory");
        var powershell = Path.Combine(windows, "System32", "WindowsPowerShell", "v1.0", "powershell.exe");
        if (!File.Exists(powershell))
            return BaselineObservation.Deny("powershell_unavailable");

        // No caller-controlled input is interpolated into this fixed read-only
        // PowerShell command. ActiveStore reflects applied policy, not the local
        // PersistentStore alone.
        const string script =
            "$ErrorActionPreference='Stop';" +
            "$observed=@(Get-NetFirewallProfile -PolicyStore ActiveStore -Name Private -ErrorAction Stop | " +
            "ForEach-Object { [pscustomobject]@{" +
            "Name=[string]$_.Name;" +
            "Enabled=[string]$_.Enabled;" +
            "DefaultInboundAction=[string]$_.DefaultInboundAction;" +
            "AllowInboundRules=[string]$_.AllowInboundRules" +
            "} });" +
            "ConvertTo-Json -InputObject $observed -Compress -Depth 3";
        var info = new ProcessStartInfo(powershell)
        {
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true,
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
                return BaselineObservation.Deny("profile_reader_start_failed");

            var stdout = process.StandardOutput.ReadToEndAsync();
            var stderr = process.StandardError.ReadToEndAsync();
            if (!process.WaitForExit(5000))
            {
                process.Kill(entireProcessTree: true);
                return BaselineObservation.Deny("profile_reader_timeout");
            }
            if (!Task.WaitAll([stdout, stderr], 1000))
                return BaselineObservation.Deny("profile_reader_output_timeout");
            if (process.ExitCode != 0 || !string.IsNullOrWhiteSpace(stderr.Result))
                return BaselineObservation.Deny("profile_reader_error");
            return Parse(stdout.Result);
        }
        catch (Exception)
        {
            return BaselineObservation.Deny("profile_reader_exception");
        }
    }

    internal static BaselineObservation Parse(string? output)
    {
        if (string.IsNullOrWhiteSpace(output) || output.Length > 4096)
            return BaselineObservation.Deny("invalid_profile_output");

        try
        {
            using var doc = JsonDocument.Parse(output);
            if (doc.RootElement.ValueKind != JsonValueKind.Array ||
                doc.RootElement.GetArrayLength() != 1)
                return BaselineObservation.Deny("missing_or_ambiguous_firewall_profile");

            var item = doc.RootElement[0];
            if (item.ValueKind != JsonValueKind.Object ||
                !GetText(item, "Name", out var name) ||
                !GetText(item, "Enabled", out var enabled) ||
                !GetText(item, "DefaultInboundAction", out var inbound) ||
                !GetText(item, "AllowInboundRules", out var allowRules))
                return BaselineObservation.Deny("invalid_firewall_profile_shape");

            if (name != "Private")
                return BaselineObservation.Deny("wrong_firewall_profile");
            if (enabled != "True")
                return BaselineObservation.Deny("private_firewall_not_enabled");
            if (inbound != "Block")
                return BaselineObservation.Deny("private_default_inbound_not_block");
            if (allowRules is not ("True" or "False"))
                return BaselineObservation.Deny("private_inbound_rules_unknown");

            // Baseline says nothing about other allow rules, third-party WFP
            // policies, actual packet filtering, or changes after the query.
            return new BaselineObservation(true, "private_firewall_baseline_observed_only");
        }
        catch (JsonException)
        {
            return BaselineObservation.Deny("invalid_firewall_profile_json");
        }
    }

    private static bool GetText(JsonElement obj, string name, out string value)
    {
        value = "";
        if (!obj.TryGetProperty(name, out var element) ||
            element.ValueKind != JsonValueKind.String)
            return false;
        value = element.GetString() ?? "";
        return true;
    }
}
