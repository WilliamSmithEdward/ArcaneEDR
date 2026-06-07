using System;

namespace ArcaneEDR
{
    internal static class AlertRuleCatalog
    {
        public static void Annotate(Alert alert)
        {
            if (alert == null) return;
            if (String.IsNullOrWhiteSpace(alert.Category))
            {
                alert.Category = CategoryFor(alert.RuleId);
            }
        }

        public static string CategoryFor(string ruleId)
        {
            string value = ruleId ?? "";
            if (StartsWith(value, "NET-DNS-")) return "DNS";
            if (StartsWith(value, "NET-")) return "Network";
            if (StartsWith(value, "DNS-")) return "DNS";
            if (StartsWith(value, "PS-")) return "PowerShell";
            if (StartsWith(value, "PERSIST-")) return "Persistence";
            if (StartsWith(value, "AUTH-")) return "Auth";
            if (StartsWith(value, "FILE-")) return "File";
            if (StartsWith(value, "PROC-")) return "Process";
            if (StartsWith(value, "AUDIT-PROC-")) return "Process";
            if (StartsWith(value, "RAT-")) return "RAT";
            if (StartsWith(value, "OPENAI-")) return "AI";
            if (StartsWith(value, "SERVICE-")) return "Health";
            if (StartsWith(value, "APP-")) return "Integrity";
            if (StartsWith(value, "BASELINE-")) return "Baseline";
            if (StartsWith(value, "REPUTATION-")) return "Reputation";
            if (StartsWith(value, "CUSTOM-")) return "Custom";
            if (StartsWith(value, "TEST-")) return "Test";
            return "General";
        }

        public static bool IsServiceLifecycleAlert(string ruleId)
        {
            return ruleId != null &&
                (ruleId.Equals("SERVICE-STARTED", StringComparison.OrdinalIgnoreCase) ||
                 ruleId.Equals("SERVICE-RECOVERED-AFTER-UNCLEAN-STOP", StringComparison.OrdinalIgnoreCase) ||
                 ruleId.Equals("SERVICE-STOPPED", StringComparison.OrdinalIgnoreCase));
        }

        public static bool IsKnownCategory(string category)
        {
            if (String.IsNullOrWhiteSpace(category)) return false;

            return category.Equals("Network", StringComparison.OrdinalIgnoreCase) ||
                category.Equals("DNS", StringComparison.OrdinalIgnoreCase) ||
                category.Equals("PowerShell", StringComparison.OrdinalIgnoreCase) ||
                category.Equals("Persistence", StringComparison.OrdinalIgnoreCase) ||
                category.Equals("Auth", StringComparison.OrdinalIgnoreCase) ||
                category.Equals("File", StringComparison.OrdinalIgnoreCase) ||
                category.Equals("Process", StringComparison.OrdinalIgnoreCase) ||
                category.Equals("RAT", StringComparison.OrdinalIgnoreCase) ||
                category.Equals("AI", StringComparison.OrdinalIgnoreCase) ||
                category.Equals("Health", StringComparison.OrdinalIgnoreCase) ||
                category.Equals("Integrity", StringComparison.OrdinalIgnoreCase) ||
                category.Equals("Baseline", StringComparison.OrdinalIgnoreCase) ||
                category.Equals("Reputation", StringComparison.OrdinalIgnoreCase) ||
                category.Equals("Custom", StringComparison.OrdinalIgnoreCase) ||
                category.Equals("Test", StringComparison.OrdinalIgnoreCase) ||
                category.Equals("General", StringComparison.OrdinalIgnoreCase);
        }

        private static bool StartsWith(string value, string prefix)
        {
            return value != null && value.StartsWith(prefix, StringComparison.OrdinalIgnoreCase);
        }
    }
}
