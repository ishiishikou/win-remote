using System.Diagnostics;
using System.Globalization;
using System.Text.Json;

namespace WinRemote.Network;

/// <summary>
/// Read-only diagnostic for the one intended inbound rule in Windows ActiveStore.
/// A matching rule never proves that other allow rules do not exist, or that the
/// Windows Filtering Platform is enforcing the intended scope. Never feed this
/// result into MachineEvidence.ScopedFirewallRuleVerified.
/// </summary>
public static class WindowsFirewallRuleAudit
{
    private const string RuleName = "WinRemote.LanOnly";
    private const int MaximumOutputLength = 16384;
    public sealed record ExpectedRule(
        string LocalIpv4, string ClientIpv4, int Port, string AdapterAlias, string AgentExecutable);

    public sealed record AuditResult(bool ExactRuleShapeObserved, string Reason)
    {
        public static AuditResult Deny(string reason) => new(false, reason);
    }

    /// <summary>Read only. Does not create, enable or modify any firewall rule.</summary>
    public static AuditResult Inspect(ExpectedRule expected)
    {
        if (!OperatingSystem.IsWindows())
            return AuditResult.Deny("unsupported_os");
        if (!ValidateExpected(expected))
            return AuditResult.Deny("invalid_expectation");

        var winDir = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        if (string.IsNullOrWhiteSpace(winDir))
            return AuditResult.Deny("missing_windows_directory");
        var ps = Path.Combine(winDir, "System32", "WindowsPowerShell", "v1.0", "powershell.exe");
        if (!File.Exists(ps))
            return AuditResult.Deny("powershell_unavailable");

        // The PowerShell command is a fixed literal. No user-controlled strings or
        // network data are interpolated into the command text.
        const string script =
            "$ErrorActionPreference='Stop';" +
            "$rules=@(Get-NetFirewallRule -PolicyStore ActiveStore -Name 'WinRemote.LanOnly' -ErrorAction Stop);" +
            "$records=@(foreach($rule in $rules){" +
            "$port=@($rule|Get-NetFirewallPortFilter -ErrorAction Stop);" +
            "$address=@($rule|Get-NetFirewallAddressFilter -ErrorAction Stop);" +
            "$app=@($rule|Get-NetFirewallApplicationFilter -ErrorAction Stop);" +
            "$iface=@($rule|Get-NetFirewallInterfaceFilter -ErrorAction Stop);" +
            "if($port.Count -ne 1 -or $address.Count -ne 1 -or $app.Count -ne 1 -or $iface.Count -ne 1){throw 'ambiguous filters'};" +
            "[pscustomobject]@{Name=[string]$rule.Name;Direction=[string]$rule.Direction;" +
            "Enabled=[string]$rule.Enabled;Action=[string]$rule.Action;Profile=[string]$rule.Profile;" +
            "EdgeTraversal=[string]$rule.EdgeTraversalPolicy;Protocol=[string]$port[0].Protocol;" +
            "LocalPort=@($port[0].LocalPort|ForEach-Object {[string]$_});" +
            "LocalAddress=@($address[0].LocalAddress|ForEach-Object {[string]$_});" +
            "RemoteAddress=@($address[0].RemoteAddress|ForEach-Object {[string]$_});" +
            "Program=[string]$app[0].Program;" +
            "InterfaceAlias=@($iface[0].InterfaceAlias|ForEach-Object {[string]$_})" +
            "}});" +
            "ConvertTo-Json -InputObject $records -Compress -Depth 4";
        var info = new ProcessStartInfo(ps)
        {
            UseShellExecute = false, RedirectStandardOutput = true,
            RedirectStandardError = true, CreateNoWindow = true
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
                return AuditResult.Deny("reader_start_failed");
            var stdout = process.StandardOutput.ReadToEndAsync();
            var stderr = process.StandardError.ReadToEndAsync();
            if (!process.WaitForExit(5000))
            {
                process.Kill(entireProcessTree: true);
                return AuditResult.Deny("reader_timeout");
            }
            if (!Task.WaitAll([stdout, stderr], 1000))
                return AuditResult.Deny("reader_output_timeout");
            if (process.ExitCode != 0 || !string.IsNullOrWhiteSpace(stderr.Result))
                return AuditResult.Deny("reader_error");
            return Parse(expected, stdout.Result);
        }
        catch (Exception)
        {
            return AuditResult.Deny("reader_exception");
        }
    }

    internal static AuditResult Parse(ExpectedRule expected, string? json)
    {
        if (!ValidateExpected(expected) || string.IsNullOrWhiteSpace(json) ||
            json.Length > MaximumOutputLength)
            return AuditResult.Deny("invalid_audit_input");
        try
        {
            using var doc = JsonDocument.Parse(json);
            if (doc.RootElement.ValueKind != JsonValueKind.Array ||
                doc.RootElement.GetArrayLength() != 1)
                return AuditResult.Deny("ambiguous_or_missing_firewall_rule");
            var item = doc.RootElement[0];
            if (item.ValueKind != JsonValueKind.Object ||
                !GetString(item, "Name", out var name) ||
                !GetString(item, "Direction", out var direction) ||
                !GetString(item, "Enabled", out var enabled) ||
                !GetString(item, "Action", out var action) ||
                !GetString(item, "Profile", out var profile) ||
                !GetString(item, "EdgeTraversal", out var edge) ||
                !GetString(item, "Protocol", out var protocol) ||
                !GetString(item, "Program", out var program) ||
                !GetSingleString(item, "LocalPort", out var port) ||
                !GetSingleString(item, "LocalAddress", out var local) ||
                !GetSingleString(item, "RemoteAddress", out var remote) ||
                !GetSingleString(item, "InterfaceAlias", out var adapter))
                return AuditResult.Deny("invalid_firewall_rule_shape");

            if (name != RuleName || direction != "Inbound" || enabled != "True" ||
                action != "Allow" || profile != "Private" || edge != "Block" ||
                (protocol != "TCP" && protocol != "6") ||
                port != expected.Port.ToString(CultureInfo.InvariantCulture) ||
                local != expected.LocalIpv4 ||
                (remote != expected.ClientIpv4 && remote != expected.ClientIpv4 + "/32") ||
                adapter != expected.AdapterAlias ||
                !string.Equals(program, expected.AgentExecutable, StringComparison.OrdinalIgnoreCase))
                return AuditResult.Deny("firewall_scope_mismatch");

            return new AuditResult(true, "single_rule_shape_observed_not_effective_policy");
        }
        catch (Exception)
        {
            return AuditResult.Deny("invalid_firewall_json");
        }
    }

    private static bool ValidateExpected(ExpectedRule? expected) =>
        expected is not null &&
        expected.Port is >= 1024 and <= 65535 &&
        System.Net.IPAddress.TryParse(expected.LocalIpv4, out var local) &&
        local.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork &&
        local.ToString() == expected.LocalIpv4 &&
        System.Net.IPAddress.TryParse(expected.ClientIpv4, out var client) &&
        client.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork &&
        client.ToString() == expected.ClientIpv4 &&
        !string.IsNullOrWhiteSpace(expected.AdapterAlias) &&
        expected.AdapterAlias != "*" && expected.AdapterAlias != "Any" &&
        !string.IsNullOrWhiteSpace(expected.AgentExecutable) &&
        expected.AgentExecutable != "*" && expected.AgentExecutable != "Any";

    private static bool GetString(JsonElement item, string property, out string value)
    {
        value = string.Empty;
        if (!item.TryGetProperty(property, out var v) || v.ValueKind != JsonValueKind.String)
            return false;
        value = v.GetString() ?? string.Empty;
        return true;
    }

    private static bool GetSingleString(JsonElement item, string property, out string value)
    {
        value = string.Empty;
        if (!item.TryGetProperty(property, out var array) ||
            array.ValueKind != JsonValueKind.Array || array.GetArrayLength() != 1 ||
            array[0].ValueKind != JsonValueKind.String)
            return false;
        value = array[0].GetString() ?? string.Empty;
        return true;
    }
}
