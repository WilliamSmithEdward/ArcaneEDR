using System;
using System.Collections.Generic;
using System.Diagnostics.Eventing.Reader;
using System.Globalization;
using System.IO;
using System.ServiceProcess;
using System.Text.RegularExpressions;
using System.Web.Script.Serialization;

namespace ArcaneEDR
{
    internal sealed class SupportBundleGenerator
    {
        private const int MaxRecentAlertLines = 80;
        private const int MaxRecentErrorLines = 120;
        private readonly MonitorConfig config;
        private readonly string baseDirectory;

        public SupportBundleGenerator(MonitorConfig config, string baseDirectory)
        {
            this.config = config;
            this.baseDirectory = baseDirectory;
        }

        public string Generate()
        {
            string bundleDirectory = Path.Combine(
                config.LogDirectory,
                "ArcaneSupportBundle-" + DateTime.UtcNow.ToString("yyyyMMddHHmmss", CultureInfo.InvariantCulture));
            Directory.CreateDirectory(bundleDirectory);

            WriteManifest(bundleDirectory);
            WriteRedactedConfig(bundleDirectory);
            WriteHealthState(bundleDirectory);
            WriteRuntimeChecks(bundleDirectory);
            WriteRecentAlerts(bundleDirectory);
            WriteRecentErrors(bundleDirectory);
            WriteRecentIncidents(bundleDirectory);
            WriteRecentAgentActivity(bundleDirectory);

            return bundleDirectory;
        }

        private void WriteManifest(string bundleDirectory)
        {
            List<string> lines = new List<string>();
            lines.Add("Product=" + config.ProductName);
            lines.Add("Version=" + VersionInfo.DisplayVersion);
            lines.Add("Repository=" + VersionInfo.RepositoryUrl);
            lines.Add("GeneratedUtc=" + Format(DateTime.UtcNow));
            lines.Add("Machine=<redacted-host>");
            lines.Add("BaseDirectory=" + RedactPath(baseDirectory));
            lines.Add("ConfigPath=" + RedactPath(config.ConfigPath));
            lines.Add("LogDirectory=" + RedactPath(config.LogDirectory));
            lines.Add("ServiceName=" + config.ServiceName);
            lines.Add("ServiceDisplayName=" + config.ServiceDisplayName);
            lines.Add("ExternalAlertProviders=" + String.Join(",", ToList(config.GetExternalAlertProviders()).ToArray()));
            lines.Add("ResponseMode=" + config.ResponseMode);
            lines.Add("BaselineEnabled=" + config.BaselineEnabled);
            lines.Add("BaselineLearningMode=" + config.BaselineLearningMode);
            lines.Add("OpenAiLogAnalysisEnabled=" + config.EnableOpenAiLogAnalysis);
            lines.Add("IncidentGroupingEnabled=" + config.EnableIncidentGrouping);
            lines.Add("AgentActivityLedgerEnabled=" + config.EnableAgentActivityLedger);
            WriteLines(Path.Combine(bundleDirectory, "manifest.txt"), lines);
        }

        private void WriteRedactedConfig(string bundleDirectory)
        {
            List<string> lines = new List<string>();
            lines.Add("# Redacted Arcane EDR config. Values likely to contain secrets, emails, URLs, paths, domains, IPs, hashes, process lists, or local identifiers are redacted.");

            if (!File.Exists(config.ConfigPath))
            {
                lines.Add("# Config file not found: " + RedactPath(config.ConfigPath));
                WriteLines(Path.Combine(bundleDirectory, "redacted-config.txt"), lines);
                return;
            }

            foreach (string rawLine in File.ReadAllLines(config.ConfigPath))
            {
                string line = rawLine.Trim();
                if (line.Length == 0 || line.StartsWith("#", StringComparison.Ordinal))
                {
                    lines.Add(rawLine);
                    continue;
                }

                int equals = rawLine.IndexOf('=');
                if (equals <= 0)
                {
                    lines.Add(RedactSensitiveText(rawLine));
                    continue;
                }

                string key = rawLine.Substring(0, equals).Trim();
                string value = rawLine.Substring(equals + 1).Trim();
                lines.Add(key + "=" + (ShouldRedactConfigValue(key, value) ? "<redacted>" : RedactSensitiveText(value)));
            }

            WriteLines(Path.Combine(bundleDirectory, "redacted-config.txt"), lines);
        }

        private void WriteHealthState(string bundleDirectory)
        {
            string path = Path.Combine(config.LogDirectory, "ArcaneServiceHealth.state");
            HealthState state = HealthState.Load(path);
            List<string> lines = new List<string>();
            lines.Add("StateFile=" + RedactPath(path));
            lines.Add("Running=" + state.Running);
            lines.Add("LastStartUtc=" + Format(state.LastStartUtc));
            lines.Add("LastCleanStopUtc=" + Format(state.LastCleanStopUtc));
            lines.Add("LastHeartbeatUtc=" + Format(state.LastHeartbeatUtc));
            lines.Add("LastDailySummaryUtc=" + Format(state.LastDailySummaryUtc));
            lines.Add("LastOpenAiAnalysisUtc=" + Format(state.LastOpenAiAnalysisUtc));
            lines.Add("LastRunId=" + RedactSensitiveText(state.LastRunId));
            lines.Add("PollCount=" + state.PollCount.ToString(CultureInfo.InvariantCulture));
            lines.Add("AlertCount=" + state.AlertCount.ToString(CultureInfo.InvariantCulture));
            lines.Add("PollFailures=" + state.PollFailures.ToString(CultureInfo.InvariantCulture));
            lines.Add("ExternalSendFailures=" + state.ExternalSendFailures.ToString(CultureInfo.InvariantCulture));
            WriteLines(Path.Combine(bundleDirectory, "health-state.txt"), lines);
        }

        private void WriteRuntimeChecks(string bundleDirectory)
        {
            List<string> lines = new List<string>();
            lines.Add("Collectors");
            lines.Add("Sysmon=" + config.EnableSysmonIngestion);
            lines.Add("PowerShell=" + config.EnablePowerShellLogIngestion);
            lines.Add("WindowsEvent=" + config.EnableWindowsEventIngestion);
            lines.Add("PersistenceInventory=" + config.EnablePersistenceInventory);
            lines.Add("");
            lines.Add("AlertSinks");
            foreach (string provider in config.GetExternalAlertProviders())
            {
                lines.Add(provider);
            }

            lines.Add("");
            lines.Add("Sysmon");
            lines.Add("ServiceName=" + config.SysmonServiceName);
            lines.Add("Status=" + ProbeService(config.SysmonServiceName));
            lines.Add("EventLog=" + config.SysmonEventLogName + " " + ProbeEventLog(config.SysmonEventLogName));
            lines.Add("");
            lines.Add("EventLogs");
            if (config.EnablePowerShellLogIngestion)
            {
                lines.Add(config.PowerShellEventLogName + " " + ProbeEventLog(config.PowerShellEventLogName));
            }

            if (config.EnableWindowsEventIngestion)
            {
                lines.Add(config.WindowsSecurityEventLogName + " " + ProbeEventLog(config.WindowsSecurityEventLogName));
                lines.Add(config.WindowsSystemEventLogName + " " + ProbeEventLog(config.WindowsSystemEventLogName));
            }

            WriteLines(Path.Combine(bundleDirectory, "runtime-checks.txt"), lines);
        }

        private void WriteRecentAlerts(string bundleDirectory)
        {
            string alertsPath = Path.Combine(config.LogDirectory, "ArcaneAlerts.jsonl");
            List<string> output = new List<string>();
            foreach (string line in Tail(alertsPath, MaxRecentAlertLines))
            {
                string summary = SummarizeAlertJson(line);
                if (!String.IsNullOrWhiteSpace(summary)) output.Add(summary);
            }

            WriteLines(Path.Combine(bundleDirectory, "recent-alerts-summary.jsonl"), output);
        }

        private void WriteRecentErrors(string bundleDirectory)
        {
            string logPath = Path.Combine(config.LogDirectory, "ArcaneEDR.log");
            List<string> errors = new List<string>();
            foreach (string line in Tail(logPath, 1000))
            {
                if (line.IndexOf(" ERROR ", StringComparison.OrdinalIgnoreCase) >= 0 ||
                    line.IndexOf(" WARN ", StringComparison.OrdinalIgnoreCase) >= 0)
                {
                    errors.Add(RedactSensitiveText(line));
                }
            }

            if (errors.Count > MaxRecentErrorLines)
            {
                errors = errors.GetRange(errors.Count - MaxRecentErrorLines, MaxRecentErrorLines);
            }

            WriteLines(Path.Combine(bundleDirectory, "recent-errors.txt"), errors);
        }

        private void WriteRecentIncidents(string bundleDirectory)
        {
            if (!config.EnableIncidentGrouping)
            {
                WriteLines(Path.Combine(bundleDirectory, "incidents-summary.txt"), new[] { "Incident grouping disabled." });
                return;
            }

            IncidentStore store = new IncidentStore(config, null);
            List<IncidentSummary> summaries = store.ListSummaries(TimeSpan.FromHours(24));
            List<string> lines = new List<string>();
            foreach (IncidentSummary summary in summaries)
            {
                lines.Add(summary.IncidentId +
                    " last=" + IncidentStore.FormatUtc(summary.LastSeenUtc) +
                    " first=" + IncidentStore.FormatUtc(summary.FirstSeenUtc) +
                    " count=" + summary.AlertCount.ToString(CultureInfo.InvariantCulture) +
                    " max=" + summary.MaxScore.ToString(CultureInfo.InvariantCulture) +
                    " severity=" + RedactSensitiveText(summary.Severity) +
                    " category=" + RedactSensitiveText(summary.Category) +
                    " maintenance_context=" + summary.HasMaintenanceContext +
                    " user=<redacted>" +
                    " process=" + RedactSensitiveText(summary.Process));
                lines.Add("  latest=" + RedactSensitiveText(summary.LatestTitle));
                lines.Add("  rules=" + String.Join(",", summary.RuleIds.ToArray()));
            }

            WriteLines(Path.Combine(bundleDirectory, "incidents-summary.txt"), lines);
        }

        private void WriteRecentAgentActivity(string bundleDirectory)
        {
            if (!config.EnableAgentActivityLedger)
            {
                WriteLines(Path.Combine(bundleDirectory, "agent-activity-summary.jsonl"), new[] { "{\"enabled\":false}" });
                return;
            }

            List<string> output = new List<string>();
            foreach (string line in Tail(config.AgentActivityLedgerFile, MaxRecentAlertLines))
            {
                string summary = SummarizeAgentActivityJson(line);
                if (!String.IsNullOrWhiteSpace(summary)) output.Add(summary);
            }

            if (output.Count == 0)
            {
                output.Add("{\"enabled\":true,\"records\":0}");
            }

            WriteLines(Path.Combine(bundleDirectory, "agent-activity-summary.jsonl"), output);
        }

        private static string SummarizeAlertJson(string line)
        {
            try
            {
                JavaScriptSerializer serializer = new JavaScriptSerializer();
                Dictionary<string, object> parsed = serializer.Deserialize<Dictionary<string, object>>(line);
                if (parsed == null) return "";

                Dictionary<string, object> summary = new Dictionary<string, object>();
                Copy(parsed, summary, "timestamp_utc");
                Copy(parsed, summary, "system_local_time");
                Copy(parsed, summary, "system_time_zone");
                Copy(parsed, summary, "system_utc_offset");
                Copy(parsed, summary, "rule_id");
                Copy(parsed, summary, "category");
                Copy(parsed, summary, "maintenance_context");
                Copy(parsed, summary, "severity");
                Copy(parsed, summary, "score");
                Copy(parsed, summary, "title");
                Copy(parsed, summary, "why");
                return serializer.Serialize(summary);
            }
            catch
            {
                return "";
            }
        }

        private static string SummarizeAgentActivityJson(string line)
        {
            try
            {
                JavaScriptSerializer serializer = new JavaScriptSerializer();
                Dictionary<string, object> parsed = serializer.Deserialize<Dictionary<string, object>>(line);
                if (parsed == null) return "";

                Dictionary<string, object> summary = new Dictionary<string, object>();
                Copy(parsed, summary, "timestamp_utc");
                Copy(parsed, summary, "system_local_time");
                Copy(parsed, summary, "system_time_zone");
                Copy(parsed, summary, "system_utc_offset");
                Copy(parsed, summary, "rule_id");
                Copy(parsed, summary, "category");
                Copy(parsed, summary, "severity");
                Copy(parsed, summary, "score");
                Copy(parsed, summary, "maintenance_context");
                Copy(parsed, summary, "process_family");
                Copy(parsed, summary, "parent_family");
                Copy(parsed, summary, "agent_reason_labels");
                Copy(parsed, summary, "command_category");
                Copy(parsed, summary, "endpoint_category");
                Copy(parsed, summary, "file_category");
                return serializer.Serialize(summary);
            }
            catch
            {
                return "";
            }
        }

        private static void Copy(Dictionary<string, object> source, Dictionary<string, object> target, string key)
        {
            object value;
            if (source.TryGetValue(key, out value))
            {
                target[key] = value;
            }
        }

        private static string ProbeService(string serviceName)
        {
            try
            {
                using (ServiceController controller = new ServiceController(serviceName))
                {
                    return controller.Status.ToString();
                }
            }
            catch (Exception ex)
            {
                return "not-readable: " + RedactSensitiveText(ex.Message);
            }
        }

        private static string ProbeEventLog(string logName)
        {
            try
            {
                EventLogQuery query = new EventLogQuery(logName, PathType.LogName, "*[System[TimeCreated[timediff(@SystemTime) <= 600000]]]");
                using (EventLogReader reader = new EventLogReader(query))
                {
                    EventRecord record = reader.ReadEvent();
                    if (record != null) record.Dispose();
                }

                return "readable";
            }
            catch (Exception ex)
            {
                return "not-readable: " + RedactSensitiveText(ex.Message);
            }
        }

        private static List<string> Tail(string path, int maxLines)
        {
            List<string> result = new List<string>();
            try
            {
                if (!File.Exists(path)) return result;
                string[] lines = File.ReadAllLines(path);
                int start = Math.Max(0, lines.Length - maxLines);
                for (int index = start; index < lines.Length; index++)
                {
                    result.Add(lines[index]);
                }
            }
            catch
            {
            }

            return result;
        }

        private static bool ShouldRedactConfigValue(string key, string value)
        {
            string normalized = (key ?? "").ToLowerInvariant();
            if (normalized.IndexOf("key", StringComparison.Ordinal) >= 0) return true;
            if (normalized.IndexOf("secret", StringComparison.Ordinal) >= 0) return true;
            if (normalized.IndexOf("password", StringComparison.Ordinal) >= 0) return true;
            if (normalized.IndexOf("token", StringComparison.Ordinal) >= 0) return true;
            if (normalized.IndexOf("email", StringComparison.Ordinal) >= 0) return true;
            if (normalized.IndexOf("recipient", StringComparison.Ordinal) >= 0) return true;
            if (normalized.IndexOf("sender", StringComparison.Ordinal) >= 0) return true;
            if (normalized.IndexOf("url", StringComparison.Ordinal) >= 0) return true;
            if (normalized.IndexOf("path", StringComparison.Ordinal) >= 0) return true;
            if (normalized.IndexOf("directory", StringComparison.Ordinal) >= 0) return true;
            if (normalized.IndexOf("file", StringComparison.Ordinal) >= 0) return true;
            if (normalized.IndexOf("root", StringComparison.Ordinal) >= 0) return true;
            if (normalized.IndexOf("domain", StringComparison.Ordinal) >= 0) return true;
            if (normalized.IndexOf("hash", StringComparison.Ordinal) >= 0) return true;
            if (normalized.IndexOf("cidr", StringComparison.Ordinal) >= 0) return true;
            if (normalized.IndexOf("resolver", StringComparison.Ordinal) >= 0) return true;
            if (normalized.IndexOf("process", StringComparison.Ordinal) >= 0) return true;
            if (normalized.IndexOf("term", StringComparison.Ordinal) >= 0) return true;
            return LooksPrivate(value);
        }

        private static bool LooksPrivate(string value)
        {
            if (String.IsNullOrWhiteSpace(value)) return false;
            if (value.IndexOf("\\", StringComparison.Ordinal) >= 0) return true;
            if (value.IndexOf("@", StringComparison.Ordinal) >= 0) return true;
            if (value.IndexOf("http://", StringComparison.OrdinalIgnoreCase) >= 0) return true;
            if (value.IndexOf("https://", StringComparison.OrdinalIgnoreCase) >= 0) return true;
            return Regex.IsMatch(value, @"\b(?:\d{1,3}\.){3}\d{1,3}\b");
        }

        private static string RedactSensitiveText(string value)
        {
            if (String.IsNullOrWhiteSpace(value)) return "";
            string result = value;
            result = Regex.Replace(result, @"[A-Z]:\\[^\s\|,;]+", "<redacted-path>", RegexOptions.IgnoreCase);
            result = Regex.Replace(result, @"https?://[^\s\|,;]+", "<redacted-url>", RegexOptions.IgnoreCase);
            result = Regex.Replace(result, @"[A-Z0-9._%+\-]+@[A-Z0-9.\-]+\.[A-Z]{2,}", "<redacted-email>", RegexOptions.IgnoreCase);
            result = Regex.Replace(result, @"\b(?:\d{1,3}\.){3}\d{1,3}\b", "<redacted-ip>");
            result = Regex.Replace(result, @"(?i)(api[_-]?key|secret|password|token)=\S+", "$1=<redacted>");
            return result;
        }

        private static string RedactPath(string value)
        {
            if (String.IsNullOrWhiteSpace(value)) return "";
            return RedactSensitiveText(value);
        }

        private static List<string> ToList(IEnumerable<string> values)
        {
            List<string> result = new List<string>();
            foreach (string value in values)
            {
                result.Add(value);
            }

            return result;
        }

        private static string Format(DateTime value)
        {
            return value.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ", CultureInfo.InvariantCulture);
        }

        private static string Format(DateTime? value)
        {
            return value.HasValue ? Format(value.Value) : "";
        }

        private static void WriteLines(string path, IEnumerable<string> lines)
        {
            Directory.CreateDirectory(Path.GetDirectoryName(path));
            File.WriteAllLines(path, ToList(lines).ToArray());
        }
    }
}
