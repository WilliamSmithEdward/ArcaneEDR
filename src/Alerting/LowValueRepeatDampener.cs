using System;
using System.Collections.Generic;

namespace ArcaneEDR
{
    internal sealed class LowValueRepeatDampener
    {
        private readonly MonitorConfig config;
        private readonly Dictionary<string, Queue<DateTime>> sightings = new Dictionary<string, Queue<DateTime>>(StringComparer.OrdinalIgnoreCase);

        public LowValueRepeatDampener(MonitorConfig config)
        {
            this.config = config;
        }

        public bool ShouldDampen(Alert alert)
        {
            if (alert == null || config == null || !config.EnableLowValueRepeatDampening)
            {
                return false;
            }

            if (alert.Score > config.LowValueRepeatDampeningMaximumScore)
            {
                return false;
            }

            if (config.LowValueRepeatDampeningWindowMinutes <= 0 ||
                config.LowValueRepeatDampeningMaxExternalAlertsPerWindow <= 0)
            {
                return false;
            }

            string category = AlertRulePolicy.AlertCategory(alert);
            if (config.LowValueRepeatDampeningCategories.Count == 0 ||
                !config.LowValueRepeatDampeningCategories.Contains(category))
            {
                return false;
            }

            string key = BuildRepeatKey(alert, category);
            if (String.IsNullOrWhiteSpace(key))
            {
                return false;
            }

            DateTime now = DateTime.UtcNow;
            DateTime cutoff = now.AddMinutes(-config.LowValueRepeatDampeningWindowMinutes);

            Queue<DateTime> queue;
            if (!sightings.TryGetValue(key, out queue))
            {
                queue = new Queue<DateTime>();
                sightings[key] = queue;
            }

            while (queue.Count > 0 && queue.Peek() < cutoff)
            {
                queue.Dequeue();
            }

            queue.Enqueue(now);
            return queue.Count > config.LowValueRepeatDampeningMaxExternalAlertsPerWindow;
        }

        private static string BuildRepeatKey(Alert alert, string category)
        {
            string ruleId = alert.RuleId ?? "";
            string entity = alert.EntitySummary ?? "";
            string process = ExtractToken(entity, "process");
            string parent = ExtractToken(entity, "parent");
            string protocol = ExtractToken(entity, "protocol");
            string processPath = FileNameOrValue(ExtractToken(entity, "process_path"));

            if (AlertRuleTaxonomy.HasPrefix(ruleId, AlertRuleTaxonomy.PrefixNetworkListen))
            {
                return Join(ruleId, FirstNonEmpty(process, "unknown-process"), parent, protocol, ExtractToken(entity, "local"));
            }

            if (category.Equals("Network", StringComparison.OrdinalIgnoreCase) ||
                category.Equals("RAT", StringComparison.OrdinalIgnoreCase))
            {
                return Join(ruleId, FirstNonEmpty(process, "unknown-process"), parent, protocol, processPath);
            }

            if (category.Equals("DNS", StringComparison.OrdinalIgnoreCase) ||
                AlertRuleTaxonomy.IsDnsRule(ruleId))
            {
                return Join(ruleId, FirstNonEmpty(process, "unknown-process"), parent, processPath);
            }

            if (category.Equals("Baseline", StringComparison.OrdinalIgnoreCase))
            {
                return Join(ruleId, FirstNonEmpty(process, "unknown-process"), parent, processPath);
            }

            if (category.Equals("Reputation", StringComparison.OrdinalIgnoreCase) ||
                category.Equals("Process", StringComparison.OrdinalIgnoreCase))
            {
                return Join(ruleId, FirstNonEmpty(process, "unknown-process"), parent, FileNameOrValue(FirstNonEmpty(ExtractToken(entity, "image"), processPath)));
            }

            return Join(ruleId, alert.CooldownKey);
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
            return text.Substring(start, end - start).Trim();
        }

        private static string FirstNonEmpty(params string[] values)
        {
            foreach (string value in values)
            {
                if (!String.IsNullOrWhiteSpace(value)) return value;
            }

            return "";
        }

        private static string FileNameOrValue(string value)
        {
            if (String.IsNullOrWhiteSpace(value)) return "";

            try
            {
                string fileName = System.IO.Path.GetFileName(value);
                if (!String.IsNullOrWhiteSpace(fileName)) return fileName;
            }
            catch
            {
            }

            return value;
        }

        private static string Join(params string[] values)
        {
            List<string> parts = new List<string>();
            foreach (string value in values)
            {
                string normalized = Normalize(value);
                if (normalized.Length > 0) parts.Add(normalized);
            }

            return String.Join("|", parts.ToArray());
        }

        private static string Normalize(string value)
        {
            if (String.IsNullOrWhiteSpace(value)) return "";
            return value.Trim().ToLowerInvariant();
        }

    }
}
