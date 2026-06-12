using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading.Tasks;

namespace ArcaneEDR_Gui.Services;

internal sealed class ArcaneHealthSnapshot
{
    public string ServiceState { get; set; } = "Unknown";
    public string LastStartUtc { get; set; } = "";
    public string LastHeartbeatUtc { get; set; } = "";
    public string LastDailySummaryUtc { get; set; } = "";
    public string LastAIAnalysisUtc { get; set; } = "";
    public string PollCount { get; set; } = "0";
    public string AlertCount { get; set; } = "0";
    public string PollFailures { get; set; } = "0";
    public string ExternalSendFailures { get; set; } = "0";
    public string HealthFile { get; set; } = "";
}

internal static class ArcaneStateReader
{
    public static async Task<ArcaneHealthSnapshot> ReadHealthAsync()
    {
        ArcaneCommandResult result = await ArcaneCommandRunner.RunAsync("--health", "--json");
        ArcaneHealthSnapshot? snapshot = TryParseHealthJson(result.CombinedText());
        return snapshot ?? ReadHealth();
    }

    public static ArcaneHealthSnapshot ReadHealth()
    {
        ArcanePaths paths = ArcanePaths.Discover();
        string healthFile = paths.HealthStateFile();
        Dictionary<string, string> values = ReadKeyValueFile(healthFile);

        return new ArcaneHealthSnapshot
        {
            ServiceState = ReadServiceState(),
            LastStartUtc = Value(values, "LastStartUtc"),
            LastHeartbeatUtc = Value(values, "LastHeartbeatUtc"),
            LastDailySummaryUtc = Value(values, "LastDailySummaryUtc"),
            LastAIAnalysisUtc = Value(values, "LastAIAnalysisUtc"),
            PollCount = Value(values, "PollCount", "0"),
            AlertCount = Value(values, "AlertCount", "0"),
            PollFailures = Value(values, "PollFailures", "0"),
            ExternalSendFailures = Value(values, "ExternalSendFailures", "0"),
            HealthFile = healthFile
        };
    }

    public static string ReadRecentAlerts(int maxLines)
    {
        string path = ArcanePaths.Discover().AlertsFile();
        if (!File.Exists(path)) return "No local alert JSONL file found at " + path + ".";

        string[] lines = File.ReadAllLines(path);
        return String.Join(Environment.NewLine, lines.Skip(Math.Max(0, lines.Length - maxLines)));
    }

    public static string BuildPathSummary()
    {
        ArcanePaths paths = ArcanePaths.Discover();
        return "ProductRoot=" + paths.ProductRoot + Environment.NewLine +
            "ServiceExecutable=" + paths.ServiceExecutable + Environment.NewLine +
            "ConfigFile=" + paths.ConfigFile + Environment.NewLine +
            "DeploymentConfigFile=" + paths.DeploymentConfigFile + Environment.NewLine +
            "PolicyFile=" + paths.PolicyFile + Environment.NewLine +
            "LogDirectory=" + paths.LogDirectory + Environment.NewLine +
            "UsingExampleConfig=" + paths.UsesExampleConfig;
    }

    private static Dictionary<string, string> ReadKeyValueFile(string path)
    {
        Dictionary<string, string> values = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        if (String.IsNullOrWhiteSpace(path) || !File.Exists(path)) return values;

        foreach (string line in File.ReadAllLines(path))
        {
            int equals = line.IndexOf('=');
            if (equals <= 0) continue;
            values[line.Substring(0, equals).Trim()] = line.Substring(equals + 1).Trim();
        }

        return values;
    }

    private static string ReadServiceState()
    {
        try
        {
            using System.Diagnostics.Process process = new System.Diagnostics.Process();
            process.StartInfo = new System.Diagnostics.ProcessStartInfo
            {
                FileName = "sc.exe",
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true
            };
            process.StartInfo.ArgumentList.Add("query");
            process.StartInfo.ArgumentList.Add("ArcaneEDR");
            process.Start();
            string output = process.StandardOutput.ReadToEnd();
            process.WaitForExit(3000);
            if (output.IndexOf("RUNNING", StringComparison.OrdinalIgnoreCase) >= 0) return "Running";
            if (output.IndexOf("STOPPED", StringComparison.OrdinalIgnoreCase) >= 0) return "Stopped";
            if (output.IndexOf("PAUSED", StringComparison.OrdinalIgnoreCase) >= 0) return "Paused";
            return process.ExitCode == 0 ? "Installed" : "NotInstalledOrUnreadable";
        }
        catch
        {
            return "NotInstalledOrUnreadable";
        }
    }

    private static string Value(Dictionary<string, string> values, string key, string fallback = "")
    {
        string? value;
        return values.TryGetValue(key, out value) && !String.IsNullOrWhiteSpace(value) ? value : fallback;
    }

    private static ArcaneHealthSnapshot? TryParseHealthJson(string text)
    {
        string trimmed = text.Trim();
        if (!trimmed.StartsWith("{", StringComparison.Ordinal)) return null;

        try
        {
            HealthJson? json = JsonSerializer.Deserialize<HealthJson>(trimmed, GuiJson.CaseInsensitiveOptions);
            if (json == null) return null;

            return new ArcaneHealthSnapshot
            {
                ServiceState = String.IsNullOrWhiteSpace(json.ServiceState) ? "Unknown" : json.ServiceState,
                LastStartUtc = json.LastStartUtc ?? "",
                LastHeartbeatUtc = json.LastHeartbeatUtc ?? "",
                LastDailySummaryUtc = json.LastDailySummaryUtc ?? "",
                LastAIAnalysisUtc = json.LastAIAnalysisUtc ?? "",
                PollCount = json.PollCount.ToString(),
                AlertCount = json.AlertCount.ToString(),
                PollFailures = json.PollFailures.ToString(),
                ExternalSendFailures = json.ExternalSendFailures.ToString(),
                HealthFile = json.HealthFile ?? ""
            };
        }
        catch
        {
            return null;
        }
    }

    private sealed class HealthJson
    {
        [JsonPropertyName("service_state")]
        public string? ServiceState { get; set; }

        [JsonPropertyName("last_start_utc")]
        public string? LastStartUtc { get; set; }

        [JsonPropertyName("last_heartbeat_utc")]
        public string? LastHeartbeatUtc { get; set; }

        [JsonPropertyName("last_daily_summary_utc")]
        public string? LastDailySummaryUtc { get; set; }

        [JsonPropertyName("last_ai_analysis_utc")]
        public string? LastAIAnalysisUtc { get; set; }

        [JsonPropertyName("poll_count")]
        public long PollCount { get; set; }

        [JsonPropertyName("alert_count")]
        public long AlertCount { get; set; }

        [JsonPropertyName("poll_failures")]
        public long PollFailures { get; set; }

        [JsonPropertyName("external_send_failures")]
        public long ExternalSendFailures { get; set; }

        [JsonPropertyName("health_file")]
        public string? HealthFile { get; set; }
    }
}
