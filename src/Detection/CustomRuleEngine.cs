using System;
using System.Collections.Generic;
using System.IO;
using System.Web.Script.Serialization;

namespace ArcaneEDR
{
    internal sealed class CustomRuleEngine
    {
        private readonly MonitorConfig config;
        private readonly FileLogger logger;
        private List<CustomDetectionRule> rules;
        private DateTime loadedWriteUtc = DateTime.MinValue;

        public CustomRuleEngine(MonitorConfig config, FileLogger logger)
        {
            this.config = config;
            this.logger = logger;
        }

        public List<Alert> AnalyzePowerShell(PowerShellEvent ev)
        {
            return Analyze("powershell", ev.SearchText, "", ev.EntitySummary, "custom|powershell|" + ev.CooldownKey);
        }

        public List<Alert> AnalyzeWindowsEvent(WindowsAuditEvent ev)
        {
            return Analyze("windows", ev.SearchText, FileName(ev.ProcessName), ev.EntitySummary, "custom|windows|" + ev.CooldownKey);
        }

        public List<Alert> AnalyzePersistence(PersistenceItem item)
        {
            return Analyze("persistence", item.SearchText, FileName(item.Command), item.EntitySummary, "custom|persistence|" + item.Identity);
        }

        public List<Alert> AnalyzeProcess(SysmonProcessEvent process)
        {
            return Analyze("process", process.EntitySummary, process.ProcessName, process.EntitySummary, "custom|process|" + process.RecordId);
        }

        public List<Alert> AnalyzeEndpoint(NetworkEndpoint endpoint)
        {
            return Analyze("network", endpoint.EntitySummary, endpoint.ProcessName, endpoint.EntitySummary, "custom|network|" + endpoint.ConnectionKey);
        }

        public static List<CustomDetectionRule> LoadRules(string path)
        {
            if (String.IsNullOrWhiteSpace(path) || !File.Exists(path))
            {
                return new List<CustomDetectionRule>();
            }

            string json = File.ReadAllText(path);
            JavaScriptSerializer serializer = new JavaScriptSerializer();
            List<CustomDetectionRule> parsed = serializer.Deserialize<List<CustomDetectionRule>>(json);
            return parsed ?? new List<CustomDetectionRule>();
        }

        private List<Alert> Analyze(string source, string text, string processName, string entity, string cooldownBase)
        {
            List<Alert> alerts = new List<Alert>();
            foreach (CustomDetectionRule rule in GetRules())
            {
                if (!RuleApplies(rule, source, text, processName)) continue;

                string id = String.IsNullOrWhiteSpace(rule.id) ? "CUSTOM-RULE" : rule.id;
                string title = String.IsNullOrWhiteSpace(rule.title) ? "Custom detection rule matched" : rule.title;
                int score = rule.score <= 0 ? 70 : rule.score;
                string recommendation = String.IsNullOrWhiteSpace(rule.recommendation)
                    ? "Review the matched telemetry and tune or remove the rule if this is expected."
                    : rule.recommendation;

                alerts.Add(Alert.Create(
                    id,
                    title,
                    score,
                    "Custom rule matched source=" + source + ". Entity: " + entity,
                    recommendation,
                    cooldownBase + "|" + id));
            }

            return alerts;
        }

        private bool RuleApplies(CustomDetectionRule rule, string source, string text, string processName)
        {
            if (rule == null) return false;

            string ruleSource = String.IsNullOrWhiteSpace(rule.source) ? "any" : rule.source.Trim();
            if (!ruleSource.Equals("any", StringComparison.OrdinalIgnoreCase) &&
                !ruleSource.Equals(source, StringComparison.OrdinalIgnoreCase))
            {
                return false;
            }

            if (rule.process_names != null && rule.process_names.Length > 0)
            {
                bool processMatched = false;
                foreach (string name in rule.process_names)
                {
                    if (!String.IsNullOrWhiteSpace(name) &&
                        processName.Equals(name.Trim(), StringComparison.OrdinalIgnoreCase))
                    {
                        processMatched = true;
                        break;
                    }
                }

                if (!processMatched) return false;
            }

            if (rule.contains_any != null && rule.contains_any.Length > 0)
            {
                foreach (string term in rule.contains_any)
                {
                    if (!String.IsNullOrWhiteSpace(term) &&
                        text.IndexOf(term, StringComparison.OrdinalIgnoreCase) >= 0)
                    {
                        return true;
                    }
                }

                return false;
            }

            return rule.process_names != null && rule.process_names.Length > 0;
        }

        private List<CustomDetectionRule> GetRules()
        {
            if (!config.EnableCustomRules)
            {
                return new List<CustomDetectionRule>();
            }

            try
            {
                DateTime writeUtc = File.Exists(config.CustomRulesFile)
                    ? File.GetLastWriteTimeUtc(config.CustomRulesFile)
                    : DateTime.MinValue;

                if (rules == null || writeUtc != loadedWriteUtc)
                {
                    rules = LoadRules(config.CustomRulesFile);
                    loadedWriteUtc = writeUtc;
                    logger.Info("Loaded " + rules.Count.ToString(System.Globalization.CultureInfo.InvariantCulture) + " custom detection rules.");
                }
            }
            catch (Exception ex)
            {
                logger.Warn("Custom rule load failed: " + ex.Message);
                rules = new List<CustomDetectionRule>();
            }

            return rules;
        }

        private static string FileName(string path)
        {
            if (String.IsNullOrWhiteSpace(path)) return "";
            string cleaned = path.Trim().Trim('"');
            int slash = Math.Max(cleaned.LastIndexOf('\\'), cleaned.LastIndexOf('/'));
            return slash >= 0 && slash + 1 < cleaned.Length ? cleaned.Substring(slash + 1) : cleaned;
        }
    }
}
