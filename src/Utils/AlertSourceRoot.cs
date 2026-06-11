using System;
using System.Collections.Generic;

namespace ArcaneEDR
{
    internal static class AlertSourceRoot
    {
        public const string GroupedCooldownPrefix = "alert-group|";

        public static bool IsGroupedSummary(Alert alert)
        {
            return alert != null &&
                alert.CooldownKey != null &&
                alert.CooldownKey.StartsWith(GroupedCooldownPrefix, StringComparison.OrdinalIgnoreCase);
        }

        public static string BuildGroupingKey(Alert alert)
        {
            return BuildKey(alert, AlertRulePolicy.AlertCategory(alert), true);
        }

        public static string BuildRepeatKey(Alert alert, string category)
        {
            return BuildKey(alert, category, false);
        }

        public static string Process(Alert alert)
        {
            string entity = alert == null ? "" : alert.EntitySummary ?? "";
            return AlertEntityTokens.FirstNonEmpty(
                AlertEntityTokens.Get(entity, "process"),
                AlertEntityTokens.FileNameOrValue(AlertEntityTokens.Get(entity, "image")),
                AlertEntityTokens.FileNameOrValue(AlertEntityTokens.Get(entity, "process_path")),
                AlertEntityTokens.Get(entity, "host_application"),
                "unknown-process");
        }

        public static string Destination(Alert alert)
        {
            string entity = alert == null ? "" : alert.EntitySummary ?? "";
            return AlertEntityTokens.FirstNonEmpty(
                AlertEntityTokens.Get(entity, "remote"),
                AlertEntityTokens.Get(entity, "remote_ip"),
                AlertEntityTokens.Get(entity, "resolved_domain"),
                AlertEntityTokens.Get(entity, "registrable_domain"),
                AlertEntityTokens.Get(entity, "sni_hostname"),
                AlertEntityTokens.Get(entity, "remote_host"),
                AlertEntityTokens.Get(entity, "query"),
                AlertEntityTokens.Get(entity, "target"),
                AlertEntityTokens.Get(entity, "name"),
                AlertEntityTokens.Get(entity, "path"),
                alert == null ? "" : alert.Title);
        }

        public static string Company(Alert alert)
        {
            string entity = alert == null ? "" : alert.EntitySummary ?? "";
            return AlertEntityTokens.FirstNonEmpty(
                AlertEntityTokens.Get(entity, "remote_owner"),
                AlertEntityTokens.Get(entity, "owner"),
                AlertEntityTokens.Get(entity, "asn_org"));
        }

        private static string BuildKey(Alert alert, string category, bool includeCategory)
        {
            if (alert == null) return "";

            string entity = alert.EntitySummary ?? "";
            string ruleId = alert.RuleId ?? "";
            string normalizedCategory = String.IsNullOrWhiteSpace(category)
                ? AlertRulePolicy.AlertCategory(alert)
                : category;
            string process = includeCategory
                ? GroupingProcess(entity)
                : AlertEntityTokens.Get(entity, "process");
            string processOrUnknown = AlertEntityTokens.FirstNonEmpty(process, "unknown-process");
            string parent = AlertEntityTokens.FirstNonEmpty(
                AlertEntityTokens.Get(entity, "parent"),
                AlertEntityTokens.FileNameOrValue(AlertEntityTokens.Get(entity, "parent_path")));
            string protocol = AlertEntityTokens.Get(entity, "protocol");
            string processPath = AlertEntityTokens.FileNameOrValue(AlertEntityTokens.Get(entity, "process_path"));

            if (AlertRuleTaxonomy.HasPrefix(ruleId, AlertRuleTaxonomy.PrefixNetworkListen))
            {
                return Join(includeCategory, ruleId, normalizedCategory, processOrUnknown, parent, protocol, AlertEntityTokens.Get(entity, "local"));
            }

            if (normalizedCategory.Equals(AlertRuleTaxonomy.CategoryNetwork, StringComparison.OrdinalIgnoreCase) ||
                normalizedCategory.Equals(AlertRuleTaxonomy.CategoryRat, StringComparison.OrdinalIgnoreCase))
            {
                return Join(includeCategory, ruleId, normalizedCategory, processOrUnknown, parent, protocol, processPath);
            }

            if (normalizedCategory.Equals(AlertRuleTaxonomy.CategoryDns, StringComparison.OrdinalIgnoreCase) ||
                AlertRuleTaxonomy.IsDnsRule(ruleId))
            {
                return Join(includeCategory, ruleId, normalizedCategory, processOrUnknown, parent, processPath);
            }

            if (normalizedCategory.Equals(AlertRuleTaxonomy.CategoryBaseline, StringComparison.OrdinalIgnoreCase))
            {
                return Join(includeCategory, ruleId, normalizedCategory, processOrUnknown, parent, processPath);
            }

            if (normalizedCategory.Equals(AlertRuleTaxonomy.CategoryReputation, StringComparison.OrdinalIgnoreCase) ||
                normalizedCategory.Equals(AlertRuleTaxonomy.CategoryProcess, StringComparison.OrdinalIgnoreCase))
            {
                string imageOrPath = AlertEntityTokens.FileNameOrValue(AlertEntityTokens.FirstNonEmpty(
                    AlertEntityTokens.Get(entity, "image"),
                    processPath));
                return Join(includeCategory, ruleId, normalizedCategory, processOrUnknown, parent, imageOrPath);
            }

            return includeCategory
                ? Join(true, ruleId, normalizedCategory, process, parent, alert.CooldownKey)
                : Join(false, ruleId, normalizedCategory, alert.CooldownKey);
        }

        private static string GroupingProcess(string entity)
        {
            return AlertEntityTokens.FirstNonEmpty(
                AlertEntityTokens.Get(entity, "process"),
                AlertEntityTokens.FileNameOrValue(AlertEntityTokens.Get(entity, "image")),
                AlertEntityTokens.FileNameOrValue(AlertEntityTokens.Get(entity, "process_path")),
                AlertEntityTokens.Get(entity, "host_application"));
        }

        private static string Join(bool includeCategory, string ruleId, string category, params string[] values)
        {
            List<string> parts = new List<string>();
            AddNormalized(parts, ruleId);
            if (includeCategory) AddNormalized(parts, category);

            foreach (string value in values)
            {
                AddNormalized(parts, value);
            }

            return String.Join("|", parts.ToArray());
        }

        private static void AddNormalized(List<string> parts, string value)
        {
            string normalized = Normalize(value);
            if (normalized.Length > 0) parts.Add(normalized);
        }

        private static string Normalize(string value)
        {
            if (String.IsNullOrWhiteSpace(value)) return "";
            return value.Trim().ToLowerInvariant();
        }
    }
}
