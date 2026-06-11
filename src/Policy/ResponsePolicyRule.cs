using System;
using System.Collections.Generic;

namespace ArcaneEDR
{
    internal sealed class ResponsePolicyRule : IScopedPolicyRule<Alert>
    {
        public const string ActionAllow = "allow";
        public const string ActionBlock = "block";

        public string Id = "";
        public string Action = "";
        public string RuleId = "";
        public string Category = "";

        public string Scope
        {
            get { return PolicyRuleScope.Response; }
        }

        public bool Allows
        {
            get { return Action.Equals(ActionAllow, StringComparison.OrdinalIgnoreCase); }
        }

        public bool Matches(Alert alert)
        {
            if (alert == null) return false;

            if (!String.IsNullOrWhiteSpace(RuleId))
            {
                return RuleId.Equals(alert.RuleId ?? "", StringComparison.OrdinalIgnoreCase);
            }

            if (!String.IsNullOrWhiteSpace(Category))
            {
                return Category.Equals(AlertRulePolicy.AlertCategory(alert), StringComparison.OrdinalIgnoreCase);
            }

            return false;
        }

        public string Reason()
        {
            string prefix = Allows ? "allowed" : "blocked";
            if (!String.IsNullOrWhiteSpace(RuleId)) return prefix + " rule id: " + RuleId;
            if (!String.IsNullOrWhiteSpace(Category)) return prefix + " category: " + Category;
            return prefix + " response policy";
        }

        public static List<ResponsePolicyRule> Build(MonitorConfig config)
        {
            List<ResponsePolicyRule> rules = new List<ResponsePolicyRule>();
            if (config == null) return rules;

            AddRules(rules, ActionBlock, "blocked-rule", config.ResponseBlockedRuleIds, true);
            AddRules(rules, ActionBlock, "blocked-category", config.ResponseBlockedCategories, false);
            AddRules(rules, ActionAllow, "allowed-rule", config.ResponseAllowedRuleIds, true);
            AddRules(rules, ActionAllow, "allowed-category", config.ResponseAllowedCategories, false);
            return rules;
        }

        public static bool HasAllowPolicy(MonitorConfig config)
        {
            return config != null &&
                (ConfiguredValues.HasAny(config.ResponseAllowedRuleIds) ||
                    ConfiguredValues.HasAny(config.ResponseAllowedCategories));
        }

        private static void AddRules(
            List<ResponsePolicyRule> rules,
            string action,
            string idPrefix,
            HashSet<string> values,
            bool ruleId)
        {
            if (rules == null || values == null) return;

            List<string> sorted = new List<string>();
            foreach (string value in values)
            {
                if (!String.IsNullOrWhiteSpace(value)) sorted.Add(value.Trim());
            }

            sorted.Sort(StringComparer.OrdinalIgnoreCase);

            foreach (string value in sorted)
            {
                ResponsePolicyRule rule = new ResponsePolicyRule();
                rule.Id = idPrefix + ":" + value;
                rule.Action = action;
                if (ruleId) rule.RuleId = value;
                else rule.Category = value;
                rules.Add(rule);
            }
        }
    }
}
