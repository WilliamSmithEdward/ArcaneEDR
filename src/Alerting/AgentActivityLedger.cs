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

            string text = AlertText.Build(alert);
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
                "\"timestamp_utc\":\"" + JsonFields.Escape(UtcTimestamp.Format(alert.TimestampUtc)) + "\"," +
                "\"system_local_time\":\"" + JsonFields.Escape(alert.SystemLocalTime) + "\"," +
                "\"system_time_zone\":\"" + JsonFields.Escape(alert.SystemTimeZoneId) + "\"," +
                "\"system_utc_offset\":\"" + JsonFields.Escape(alert.SystemUtcOffset) + "\"," +
                "\"rule_id\":\"" + JsonFields.Escape(alert.RuleId) + "\"," +
                "\"category\":\"" + JsonFields.Escape(AlertRulePolicy.AlertCategory(alert)) + "\"," +
                "\"severity\":\"" + JsonFields.Escape(alert.Severity) + "\"," +
                "\"score\":" + alert.Score.ToString(CultureInfo.InvariantCulture) + "," +
                "\"maintenance_context\":" + (alert.MaintenanceContext ? "true" : "false") + "," +
                "\"process_family\":\"" + JsonFields.Escape(ProcessFamily(text, "process")) + "\"," +
                "\"parent_family\":\"" + JsonFields.Escape(ProcessFamily(text, "parent")) + "\"," +
                "\"agent_reason_labels\":" + JsonArray(agentReasonLabels) + "," +
                "\"command_category\":\"" + JsonFields.Escape(CommandCategory(alert, text)) + "\"," +
                "\"endpoint_category\":\"" + JsonFields.Escape(EndpointCategory(alert, text)) + "\"," +
                "\"file_category\":\"" + JsonFields.Escape(FileCategory(text)) + "\"," +
                "\"rule_hit\":\"" + JsonFields.Escape(alert.RuleId) + "\"" +
                "}";
        }

        private void AppendLine(string path, string line)
        {
            lock (gate)
            {
                Directory.CreateDirectory(Path.GetDirectoryName(path));
                LogFileRotation.RotateIfNeeded(path, config.MaxLogFileBytes);
                File.AppendAllText(path, line + Environment.NewLine);
            }
        }

        private string CommandCategory(Alert alert, string text)
        {
            string ruleId = alert.RuleId ?? "";
            if (AlertRuleTaxonomy.HasPrefix(ruleId, AlertRuleTaxonomy.PrefixAgentAdmin)) return "agent-admin-command";
            if (AlertRuleTaxonomy.HasPrefix(ruleId, AlertRuleTaxonomy.PrefixAgentSecret)) return "agent-secret-reference";
            if (AlertRuleTaxonomy.HasPrefix(ruleId, AlertRuleTaxonomy.PrefixAgentSupply)) return "agent-supply-chain";
            if (AlertRuleTaxonomy.HasPrefix(ruleId, AlertRuleTaxonomy.PrefixAgent)) return "agent-guardrail";
            if (TextFormatting.ContainsIgnoreCase(ruleId, "ENCODED") || TextFormatting.ContainsIgnoreCase(text, "base64")) return "encoded";
            if (AlertRuleTaxonomy.HasPrefix(ruleId, AlertRuleTaxonomy.PrefixPowerShellDefender) || TextFormatting.ContainsIgnoreCase(text, "defender")) return "security-control-change";
            if (AlertRuleTaxonomy.HasPrefix(ruleId, AlertRuleTaxonomy.PrefixPowerShellPersistence) ||
                AlertRuleTaxonomy.HasPrefix(ruleId, AlertRuleTaxonomy.PrefixPersistence)) return "persistence";
            if (AlertRuleTaxonomy.HasPrefix(ruleId, AlertRuleTaxonomy.PrefixFile)) return "file-write";
            if (TextFormatting.ContainsIgnoreCase(ruleId, "DOWNLOAD") || TextFormatting.ContainsIgnoreCase(text, "download")) return "download-or-staging";
            if (AlertRuleTaxonomy.HasPrefix(ruleId, AlertRuleTaxonomy.PrefixNetworkLan) || TextFormatting.ContainsIgnoreCase(ruleId, "LATERAL")) return "lateral-or-admin-access";
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
            if (TextFormatting.ContainsIgnoreCase(ruleId, "DIRECT-IP")) return "external-direct-ip-web";
            if (TextFormatting.ContainsIgnoreCase(ruleId, "BEACON")) return "external-beacon-like";
            if (TextFormatting.ContainsIgnoreCase(ruleId, "HIGH-RISK-PORT") || TextFormatting.ContainsIgnoreCase(ruleId, "UNUSUAL-PORT") || TextFormatting.ContainsIgnoreCase(ruleId, "PORT-MISUSE")) return "external-unusual-port";
            if (AlertRuleTaxonomy.IsDnsRule(ruleId)) return "dns";
            if (AlertRuleTaxonomy.HasAnyPrefix(ruleId, AlertRuleTaxonomy.PrefixNetworkEgress, AlertRuleTaxonomy.PrefixRat)) return "external-egress";
            if (TextFormatting.ContainsIgnoreCase(text, "remote=")) return "network";
            return "none";
        }

        private string FileCategory(string text)
        {
            string normalized = NormalizePathText(text);
            if (TextFormatting.ContainsIgnoreCase(normalized, "\\start menu\\programs\\startup\\") || TextFormatting.ContainsIgnoreCase(normalized, "\\startup\\")) return "startup";
            if (TextFormatting.ContainsIgnoreCase(normalized, "\\windows\\system32\\tasks\\")) return "scheduled-task-storage";
            if (TextFormatting.ContainsIgnoreCase(normalized, "\\extensions\\")) return "browser-extension";
            if (ContainsAnyConfiguredRoot(normalized, config.AgentWorkspaceRoots)) return "agent-workspace";
            if (ContainsAnyConfiguredRoot(normalized, config.AgentPublishRoots)) return "agent-publish-root";
            if (ConfiguredValues.ContainsAnyNormalizedPathTerm(normalized, config.SensitiveFileNameIndicators) ||
                ConfiguredValues.ContainsAnyNormalizedPathTerm(normalized, config.AgentSecretIndicatorTerms)) return "sensitive-name";
            if (FileSystemRules.IsUserWritablePath(normalized, config)) return "user-writable";
            return "none";
        }

        private static string ProcessFamily(string text, string key)
        {
            string value = AlertEntityTokens.FirstNonEmpty(
                AlertEntityTokens.Get(text, key),
                AlertEntityTokens.Get(text, key + "_name"));
            if (String.IsNullOrWhiteSpace(value)) return "unknown";

            return SafeToken(AlertEntityTokens.FileNameOrValue(value), 80);
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

        private static string NormalizePathText(string value)
        {
            return ConfiguredValues.NormalizePathText(value);
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
                encoded.Add("\"" + JsonFields.Escape(value) + "\"");
            }

            return "[" + String.Join(",", encoded.ToArray()) + "]";
        }

    }
}
