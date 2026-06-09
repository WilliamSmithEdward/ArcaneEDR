using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;

namespace ArcaneEDR
{
    internal sealed class AgentActivityLedger
    {
        private readonly MonitorConfig config;
        private readonly FileLogger logger;
        private readonly object gate = new object();

        public AgentActivityLedger(MonitorConfig config, FileLogger logger)
        {
            this.config = config;
            this.logger = logger;
        }

        public void Record(Alert alert)
        {
            if (alert == null || config == null || !config.EnableAgentActivityLedger) return;
            if (alert.Score < config.AgentActivityLedgerMinimumScore) return;

            string text = AlertText(alert);
            if (text.IndexOf("agent_context=involved", StringComparison.OrdinalIgnoreCase) < 0) return;

            try
            {
                string json = BuildJson(alert, text);
                AppendLine(config.AgentActivityLedgerFile, json);
            }
            catch (Exception ex)
            {
                if (logger != null)
                {
                    logger.Warn("Agent activity ledger write failed: " + ex.Message);
                }
            }
        }

        private string BuildJson(Alert alert, string text)
        {
            List<string> agentReasonLabels = AgentReasonLabels(text);

            return "{" +
                "\"timestamp_utc\":\"" + JsonEscape(alert.TimestampUtc.ToString("yyyy-MM-ddTHH:mm:ssZ", CultureInfo.InvariantCulture)) + "\"," +
                "\"system_local_time\":\"" + JsonEscape(alert.SystemLocalTime) + "\"," +
                "\"system_time_zone\":\"" + JsonEscape(alert.SystemTimeZoneId) + "\"," +
                "\"system_utc_offset\":\"" + JsonEscape(alert.SystemUtcOffset) + "\"," +
                "\"rule_id\":\"" + JsonEscape(alert.RuleId) + "\"," +
                "\"category\":\"" + JsonEscape(AlertRulePolicy.AlertCategory(alert)) + "\"," +
                "\"severity\":\"" + JsonEscape(alert.Severity) + "\"," +
                "\"score\":" + alert.Score.ToString(CultureInfo.InvariantCulture) + "," +
                "\"maintenance_context\":" + (alert.MaintenanceContext ? "true" : "false") + "," +
                "\"process_family\":\"" + JsonEscape(ProcessFamily(text, "process")) + "\"," +
                "\"parent_family\":\"" + JsonEscape(ProcessFamily(text, "parent")) + "\"," +
                "\"agent_reason_labels\":" + JsonArray(agentReasonLabels) + "," +
                "\"command_category\":\"" + JsonEscape(CommandCategory(alert, text)) + "\"," +
                "\"endpoint_category\":\"" + JsonEscape(EndpointCategory(alert, text)) + "\"," +
                "\"file_category\":\"" + JsonEscape(FileCategory(text)) + "\"," +
                "\"rule_hit\":\"" + JsonEscape(alert.RuleId) + "\"" +
                "}";
        }

        private void AppendLine(string path, string line)
        {
            lock (gate)
            {
                Directory.CreateDirectory(Path.GetDirectoryName(path));
                RotateIfNeeded(path);
                File.AppendAllText(path, line + Environment.NewLine);
            }
        }

        private void RotateIfNeeded(string path)
        {
            try
            {
                FileInfo file = new FileInfo(path);
                if (!file.Exists || file.Length < config.MaxLogFileBytes) return;

                string rotated = path + "." + DateTime.UtcNow.ToString("yyyyMMddHHmmss", CultureInfo.InvariantCulture) + ".old";
                File.Move(path, rotated);
            }
            catch
            {
            }
        }

        private string CommandCategory(Alert alert, string text)
        {
            string ruleId = alert.RuleId ?? "";
            if (AlertRuleTaxonomy.HasPrefix(ruleId, AlertRuleTaxonomy.PrefixAgentAdmin)) return "agent-admin-command";
            if (AlertRuleTaxonomy.HasPrefix(ruleId, AlertRuleTaxonomy.PrefixAgentSecret)) return "agent-secret-reference";
            if (AlertRuleTaxonomy.HasPrefix(ruleId, AlertRuleTaxonomy.PrefixAgentSupply)) return "agent-supply-chain";
            if (AlertRuleTaxonomy.HasPrefix(ruleId, AlertRuleTaxonomy.PrefixAgent)) return "agent-guardrail";
            if (Contains(ruleId, "ENCODED") || Contains(text, "base64")) return "encoded";
            if (AlertRuleTaxonomy.HasPrefix(ruleId, AlertRuleTaxonomy.PrefixPowerShellDefender) || Contains(text, "defender")) return "security-control-change";
            if (AlertRuleTaxonomy.HasPrefix(ruleId, AlertRuleTaxonomy.PrefixPowerShellPersistence) ||
                AlertRuleTaxonomy.HasPrefix(ruleId, AlertRuleTaxonomy.PrefixPersistence)) return "persistence";
            if (AlertRuleTaxonomy.HasPrefix(ruleId, AlertRuleTaxonomy.PrefixFile)) return "file-write";
            if (Contains(ruleId, "DOWNLOAD") || Contains(text, "download")) return "download-or-staging";
            if (AlertRuleTaxonomy.HasPrefix(ruleId, AlertRuleTaxonomy.PrefixNetworkLan) || Contains(ruleId, "LATERAL")) return "lateral-or-admin-access";
            if (AlertRuleTaxonomy.HasAnyPrefix(ruleId, AlertRuleTaxonomy.PrefixNetwork, AlertRuleTaxonomy.PrefixDns, AlertRuleTaxonomy.PrefixRat)) return "network";
            if (AlertRuleTaxonomy.HasPrefix(ruleId, AlertRuleTaxonomy.PrefixAuth)) return "auth";
            if (AlertRuleTaxonomy.HasAnyPrefix(ruleId, AlertRuleTaxonomy.PrefixProcess, AlertRuleTaxonomy.PrefixReputation)) return "process";
            return "other";
        }

        private string EndpointCategory(Alert alert, string text)
        {
            string ruleId = alert.RuleId ?? "";
            if (AlertRuleTaxonomy.HasPrefix(ruleId, AlertRuleTaxonomy.PrefixNetworkLanInbound)) return "lan-inbound-admin";
            if (AlertRuleTaxonomy.HasPrefix(ruleId, AlertRuleTaxonomy.PrefixNetworkLanEgress)) return "lan-egress-admin";
            if (AlertRuleTaxonomy.HasPrefix(ruleId, AlertRuleTaxonomy.PrefixNetworkInbound)) return "external-inbound";
            if (Contains(ruleId, "DIRECT-IP")) return "external-direct-ip-web";
            if (Contains(ruleId, "BEACON")) return "external-beacon-like";
            if (Contains(ruleId, "HIGH-RISK-PORT") || Contains(ruleId, "UNUSUAL-PORT") || Contains(ruleId, "PORT-MISUSE")) return "external-unusual-port";
            if (AlertRuleTaxonomy.IsDnsRule(ruleId)) return "dns";
            if (AlertRuleTaxonomy.HasAnyPrefix(ruleId, AlertRuleTaxonomy.PrefixNetworkEgress, AlertRuleTaxonomy.PrefixRat)) return "external-egress";
            if (Contains(text, "remote=")) return "network";
            return "none";
        }

        private string FileCategory(string text)
        {
            string normalized = NormalizePathText(text);
            if (Contains(normalized, "\\start menu\\programs\\startup\\") || Contains(normalized, "\\startup\\")) return "startup";
            if (Contains(normalized, "\\windows\\system32\\tasks\\")) return "scheduled-task-storage";
            if (Contains(normalized, "\\extensions\\")) return "browser-extension";
            if (ContainsAnyConfiguredRoot(normalized, config.AgentWorkspaceRoots)) return "agent-workspace";
            if (ContainsAnyConfiguredRoot(normalized, config.AgentPublishRoots)) return "agent-publish-root";
            if (ContainsAnyConfigured(normalized, config.SensitiveFileNameIndicators) ||
                ContainsAnyConfigured(normalized, config.AgentSecretIndicatorTerms)) return "sensitive-name";
            if (FileSystemRules.IsUserWritablePath(normalized, config)) return "user-writable";
            return "none";
        }

        private static string ProcessFamily(string text, string key)
        {
            string value = FirstNonEmpty(ExtractToken(text, key), ExtractToken(text, key + "_name"));
            if (String.IsNullOrWhiteSpace(value)) return "unknown";

            try
            {
                string fileName = Path.GetFileName(value);
                if (!String.IsNullOrWhiteSpace(fileName)) value = fileName;
            }
            catch
            {
            }

            return SafeToken(value, 80);
        }

        private static List<string> AgentReasonLabels(string text)
        {
            List<string> labels = new List<string>();
            int index = text.IndexOf("agent_context=involved", StringComparison.OrdinalIgnoreCase);
            while (index >= 0)
            {
                int reasonsIndex = text.IndexOf("reasons=", index, StringComparison.OrdinalIgnoreCase);
                if (reasonsIndex < 0) break;
                int start = reasonsIndex + "reasons=".Length;
                int end = FindReasonEnd(text, start);
                string reasons = text.Substring(start, end - start);
                foreach (string reason in reasons.Split(','))
                {
                    string trimmed = reason.Trim();
                    int colon = trimmed.IndexOf(':');
                    string label = colon > 0 ? trimmed.Substring(0, colon) : trimmed;
                    AddUnique(labels, SafeToken(label, 64));
                }

                index = text.IndexOf("agent_context=involved", end, StringComparison.OrdinalIgnoreCase);
            }

            return labels;
        }

        private static int FindReasonEnd(string text, int start)
        {
            int end = text.Length;
            int newline = text.IndexOf('\n', start);
            if (newline >= 0 && newline < end) end = newline;
            int pipe = text.IndexOf('|', start);
            if (pipe >= 0 && pipe < end) end = pipe;
            int spaceField = text.IndexOf(" pid=", start, StringComparison.OrdinalIgnoreCase);
            if (spaceField >= 0 && spaceField < end) end = spaceField;
            return end;
        }

        private static void AddUnique(List<string> values, string value)
        {
            if (String.IsNullOrWhiteSpace(value)) return;
            foreach (string existing in values)
            {
                if (existing.Equals(value, StringComparison.OrdinalIgnoreCase)) return;
            }

            values.Add(value);
        }

        private static string ExtractToken(string text, string key)
        {
            if (String.IsNullOrWhiteSpace(text) || String.IsNullOrWhiteSpace(key)) return "";

            string prefix = key + "=";
            int index = text.IndexOf(prefix, StringComparison.OrdinalIgnoreCase);
            if (index < 0) return "";

            int start = index + prefix.Length;
            int end = text.IndexOf(' ', start);
            if (end < 0) end = text.Length;
            return text.Substring(start, end - start).Trim().Trim('"');
        }

        private static bool ContainsAnyConfigured(string text, HashSet<string> terms)
        {
            if (String.IsNullOrWhiteSpace(text) || terms == null) return false;
            foreach (string term in terms)
            {
                if (!String.IsNullOrWhiteSpace(term) &&
                    text.IndexOf(NormalizePathText(term), StringComparison.OrdinalIgnoreCase) >= 0)
                {
                    return true;
                }
            }

            return false;
        }

        private static bool ContainsAnyConfiguredRoot(string text, HashSet<string> roots)
        {
            if (String.IsNullOrWhiteSpace(text) || roots == null) return false;
            foreach (string root in roots)
            {
                string normalizedRoot = NormalizeRoot(root);
                if (!String.IsNullOrWhiteSpace(normalizedRoot) &&
                    text.IndexOf(normalizedRoot, StringComparison.OrdinalIgnoreCase) >= 0)
                {
                    return true;
                }
            }

            return false;
        }

        private static string FirstNonEmpty(string first, string second)
        {
            return !String.IsNullOrWhiteSpace(first) ? first : second;
        }

        private static bool Contains(string value, string term)
        {
            return value != null && value.IndexOf(term, StringComparison.OrdinalIgnoreCase) >= 0;
        }

        private static string NormalizePathText(string value)
        {
            return value == null ? "" : value.Replace('/', '\\');
        }

        private static string NormalizeRoot(string value)
        {
            if (String.IsNullOrWhiteSpace(value)) return "";
            return NormalizePathText(value).TrimEnd('\\') + "\\";
        }

        private static string SafeToken(string value, int maxLength)
        {
            if (String.IsNullOrWhiteSpace(value)) return "";
            string result = value.Trim()
                .Replace("\\", "/")
                .Replace("\"", "")
                .Replace(",", "_")
                .Replace(";", "_")
                .Replace("|", "_")
                .Replace("\r", "")
                .Replace("\n", "");
            return result.Length <= maxLength ? result : result.Substring(0, maxLength);
        }

        private static string JsonArray(List<string> values)
        {
            if (values == null || values.Count == 0) return "[]";

            List<string> encoded = new List<string>();
            foreach (string value in values)
            {
                encoded.Add("\"" + JsonEscape(value) + "\"");
            }

            return "[" + String.Join(",", encoded.ToArray()) + "]";
        }

        private static string JsonEscape(string value)
        {
            if (value == null) return "";
            return value
                .Replace("\\", "\\\\")
                .Replace("\"", "\\\"")
                .Replace("\r", "\\r")
                .Replace("\n", "\\n");
        }

        private static string AlertText(Alert alert)
        {
            return (alert.RuleId ?? "") + " " +
                (alert.Title ?? "") + " " +
                (alert.Body ?? "") + " " +
                (alert.EntitySummary ?? "");
        }
    }
}
