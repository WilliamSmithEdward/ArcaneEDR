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
            return AlertRuleTaxonomy.CategoryFor(ruleId);
        }

        public static bool IsServiceLifecycleAlert(string ruleId)
        {
            return AlertRuleTaxonomy.IsServiceLifecycleRule(ruleId);
        }

        public static bool IsKnownCategory(string category)
        {
            return AlertRuleTaxonomy.IsKnownCategory(category);
        }
    }
}
