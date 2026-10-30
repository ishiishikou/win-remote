using System.Diagnostics;
using System.Text.Json;

namespace WinRemote.Network;

/// <summary>
/// Informational inventory of inbound Allow rule counts in Windows Firewall
/// ActiveStore. Counts are not effective WFP policy, and never authorize a listener.
/// No firewall rule names, executable paths or network addresses are returned.
/// </summary>
public static class WindowsInboundAllowInventory
{
    public sealed record Result(
        bool Observed,
        string Reason,
        int EnabledInboundAllowRules,
        int PrivateApplicableRules,
        int WildcardRemoteRules,
        int UnclassifiedRules)
    {
        public static Result Deny(string reason) => new(false, reason, 0, 0, 0, 0);
    }

    public static Result Read()
    {
        if (!OperatingSystem.IsWindows())
            return Result.Deny("unsupported_os");

        var windows = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        if (string.IsNullOrWhiteSpace(windows))
            return Result.Deny("missing_windows_directory");
        var powershell = Path.Combine(windows, "System32", "WindowsPowerShell", "v1.0", "powershell.exe");
        if (!File.Exists(powershell))
            return Result.Deny("powershell_unavailable");

        // Fixed read-only query; no remotely supplied arguments, interface names,
        // code or firewall alterations. Filtering is only a coarse inventory.
        const string script =
            "$ErrorActionPreference='Stop';" +
            "$rules=@(Get-NetFirewallRule -PolicyStore ActiveStore -Direction Inbound -Action Allow -Enabled True -ErrorAction Stop);" +
            "if($rules.Count -gt 50000){throw 'too many rules'};" +
            "$private=0;$wildcard=0;$unknown=0;" +
            "foreach($rule in $rules){" +
            "$profile=[string]$rule.Profile;" +
            "if($profile -eq 'Any' -or $profile -match '(^|[ ,])Private($|[ ,])'){" +
            "$private++;" +
            "try{" +
            "$filters=@($rule|Get-NetFirewallAddressFilter -ErrorAction Stop);" +
            "if($filters.Count -ne 1){$unknown++;continue};" +
            "$remote=@($filters[0].RemoteAddress);" +
            "if($remote.Count -eq 0){$unknown++;continue};" +
            "if(@($remote|Where-Object {[string]$_ -eq 'Any'}).Count -gt 0){$wildcard++}" +
            "}catch{$unknown++}" +
            "}" +
            "};" +
            "$summary=[pscustomobject]@{EnabledInboundAllowRules=[int]$rules.Count;" +
            "PrivateApplicableRules=[int]$private;WildcardRemoteRules=[int]$wildcard;" +
            "UnclassifiedRules=[int]$unknown};" +
            "ConvertTo-Json -InputObject $summary -Compress";
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
            if (!process.Start()) return Result.Deny("reader_start_failed");
            var stdout = process.StandardOutput.ReadToEndAsync();
            var stderr = process.StandardError.ReadToEndAsync();
            if (!process.WaitForExit(15000))
            {
                process.Kill(entireProcessTree: true);
                return Result.Deny("reader_timeout");
            }
            if (!Task.WaitAll([stdout, stderr], 1000))
                return Result.Deny("reader_output_timeout");
            if (process.ExitCode != 0 || !string.IsNullOrWhiteSpace(stderr.Result))
                return Result.Deny("reader_error");
            return Parse(stdout.Result);
        }
        catch (Exception)
        {
            return Result.Deny("reader_exception");
        }
    }

    internal static Result Parse(string? output)
    {
        if (string.IsNullOrWhiteSpace(output) || output.Length > 2048)
            return Result.Deny("invalid_output");
        try
        {
            using var document = JsonDocument.Parse(output);
            var root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Object ||
                !TryCount(root, "EnabledInboundAllowRules", out int total) ||
                !TryCount(root, "PrivateApplicableRules", out int applicable) ||
                !TryCount(root, "WildcardRemoteRules", out int wildcard) ||
                !TryCount(root, "UnclassifiedRules", out int unknown) ||
                applicable > total || wildcard > applicable || unknown > applicable ||
                wildcard + unknown > applicable)
                return Result.Deny("invalid_count_shape");

            return new Result(true, "informational_rule_inventory_only",
                total, applicable, wildcard, unknown);
        }
        catch (JsonException)
        {
            return Result.Deny("invalid_json");
        }
    }

    private static bool TryCount(JsonElement obj, string name, out int count)
    {
        count = 0;
        return obj.TryGetProperty(name, out var el) &&
               el.ValueKind == JsonValueKind.Number &&
               el.TryGetInt32(out count) && count is >= 0 and <= 50000;
    }
}
