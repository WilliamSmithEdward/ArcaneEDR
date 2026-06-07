using System;

namespace ArcaneEDR
{
    internal static class AlertRulePolicy
    {
        public static bool IsDisabled(MonitorConfig config, Alert alert)
        {
            if (config == null || alert == null) return false;

            string ruleId = alert.RuleId ?? "";
            string category = AlertCategory(alert);

            return config.DisabledRuleIds.Contains(ruleId) ||
                config.DisabledRuleCategories.Contains(category);
        }

        public static int MinimumExternalScore(MonitorConfig config, Alert alert)
        {
            if (config == null) return 0;
            if (alert == null) return config.MinimumEmailScore;

            int score;
            if (!String.IsNullOrWhiteSpace(alert.RuleId) &&
                config.RuleMinimumEmailScores.TryGetValue(alert.RuleId, out score))
            {
                return score;
            }

            string category = AlertCategory(alert);
            if (!String.IsNullOrWhiteSpace(category) &&
                config.CategoryMinimumEmailScores.TryGetValue(category, out score))
            {
                return score;
            }

            return config.MinimumEmailScore;
        }

        public static string AlertCategory(Alert alert)
        {
            if (alert == null) return "General";
            if (!String.IsNullOrWhiteSpace(alert.Category)) return alert.Category;
            return AlertRuleCatalog.CategoryFor(alert.RuleId);
        }
    }
}
