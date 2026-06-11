using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Text;

namespace ArcaneEDR
{
    internal sealed class ExternalAlertGroupingPlanner
    {
        private const string GroupedCooldownPrefix = "alert-group|";
        private readonly MonitorConfig config;

        private static readonly string[] EntityTokenKeys = new[]
        {
            "agent_context",
            "asn",
            "asn_org",
            "command",
            "command_line",
            "country",
            "country_lookup",
            "dns_names",
            "enrichment_source",
            "event_id",
            "host_application",
            "image",
            "item",
            "local",
            "maintenance_context",
            "message",
            "name",
            "owner",
            "parent",
            "parent_command_line",
            "parent_path",
            "parent_pid",
            "path",
            "pid",
            "policy",
            "process",
            "process_command_line",
            "process_path",
            "process_sha256",
            "process_signer",
            "process_user",
            "protocol",
            "query",
            "rdns",
            "reason",
            "reasons",
            "record_id",
            "registrable_domain",
            "remote",
            "remote_host",
            "remote_ip",
            "remote_owner",
            "resolved_domain",
            "script_block",
            "service",
            "sha256",
            "signer",
            "sni_hostname",
            "source",
            "state",
            "target",
            "thread_id",
            "user"
        };

        public ExternalAlertGroupingPlanner(MonitorConfig config)
        {
            this.config = config;
        }

        public static bool IsGroupedSummary(Alert alert)
        {
            return alert != null &&
                alert.CooldownKey != null &&
                alert.CooldownKey.StartsWith(GroupedCooldownPrefix, StringComparison.OrdinalIgnoreCase);
        }

        public List<Alert> Plan(IEnumerable<Alert> alerts)
        {
            List<OrderedAlert> planned = new List<OrderedAlert>();
            Dictionary<string, GroupBucket> buckets = new Dictionary<string, GroupBucket>(StringComparer.OrdinalIgnoreCase);
            int order = 0;

            foreach (Alert alert in alerts)
            {
                if (alert == null)
                {
                    order++;
                    continue;
                }

                string key = IsGroupingCandidate(alert) ? BuildGroupKey(alert) : "";
                if (String.IsNullOrWhiteSpace(key))
                {
                    planned.Add(new OrderedAlert(order, alert));
                    order++;
                    continue;
                }

                GroupBucket bucket;
                if (!buckets.TryGetValue(key, out bucket))
                {
                    bucket = new GroupBucket(key, order, AlertRulePolicy.AlertCategory(alert));
                    buckets[key] = bucket;
                }

                bucket.Add(alert, order);
                order++;
            }

            foreach (GroupBucket bucket in buckets.Values)
            {
                if (bucket.Count >= config.ExternalAlertGroupingMinimumCount)
                {
                    planned.Add(new OrderedAlert(bucket.FirstOrder, BuildSummary(bucket)));
                    continue;
                }

                foreach (OrderedAlert item in bucket.Alerts)
                {
                    planned.Add(item);
                }
            }

            planned.Sort(delegate(OrderedAlert left, OrderedAlert right)
            {
                return left.Order.CompareTo(right.Order);
            });

            List<Alert> result = new List<Alert>();
            foreach (OrderedAlert item in planned)
            {
                result.Add(item.Alert);
            }

            return result;
        }

        private bool IsGroupingCandidate(Alert alert)
        {
            if (alert == null || config == null || !config.EnableExternalAlertGrouping) return false;
            if (alert.ExternalForcedByPolicy) return false;
            if (AlertRuleTaxonomy.IsDirectExternalRule(alert.RuleId)) return false;
            if (alert.Score > config.ExternalAlertGroupingMaximumScore) return false;

            string category = AlertRulePolicy.AlertCategory(alert);
            return config.ExternalAlertGroupingCategories.Count > 0 &&
                config.ExternalAlertGroupingCategories.Contains(category);
        }

        private static string BuildGroupKey(Alert alert)
        {
            string entity = alert.EntitySummary ?? "";
            string ruleId = alert.RuleId ?? "";
            string category = AlertRulePolicy.AlertCategory(alert);
            string process = FirstNonEmpty(
                ExtractToken(entity, "process"),
                FileNameOrValue(ExtractToken(entity, "image")),
                FileNameOrValue(ExtractToken(entity, "process_path")),
                ExtractToken(entity, "host_application"));
            string parent = FirstNonEmpty(
                ExtractToken(entity, "parent"),
                FileNameOrValue(ExtractToken(entity, "parent_path")));
            string protocol = ExtractToken(entity, "protocol");

            if (AlertRuleTaxonomy.HasPrefix(ruleId, AlertRuleTaxonomy.PrefixNetworkListen))
            {
                return Join(ruleId, category, FirstNonEmpty(process, "unknown-process"), parent, protocol, ExtractToken(entity, "local"));
            }

            if (category.Equals(AlertRuleTaxonomy.CategoryNetwork, StringComparison.OrdinalIgnoreCase) ||
                category.Equals(AlertRuleTaxonomy.CategoryRat, StringComparison.OrdinalIgnoreCase))
            {
                return Join(ruleId, category, FirstNonEmpty(process, "unknown-process"), parent, protocol, FileNameOrValue(ExtractToken(entity, "process_path")));
            }

            if (category.Equals(AlertRuleTaxonomy.CategoryDns, StringComparison.OrdinalIgnoreCase) ||
                AlertRuleTaxonomy.IsDnsRule(ruleId))
            {
                return Join(ruleId, category, FirstNonEmpty(process, "unknown-process"), parent, FileNameOrValue(ExtractToken(entity, "process_path")));
            }

            if (category.Equals(AlertRuleTaxonomy.CategoryBaseline, StringComparison.OrdinalIgnoreCase))
            {
                return Join(ruleId, category, FirstNonEmpty(process, "unknown-process"), parent, FileNameOrValue(ExtractToken(entity, "process_path")));
            }

            if (category.Equals(AlertRuleTaxonomy.CategoryReputation, StringComparison.OrdinalIgnoreCase) ||
                category.Equals(AlertRuleTaxonomy.CategoryProcess, StringComparison.OrdinalIgnoreCase))
            {
                return Join(ruleId, category, FirstNonEmpty(process, "unknown-process"), parent, FileNameOrValue(FirstNonEmpty(ExtractToken(entity, "image"), ExtractToken(entity, "process_path"))));
            }

            return Join(ruleId, category, process, parent, alert.CooldownKey);
        }

        private Alert BuildSummary(GroupBucket bucket)
        {
            string title = "Grouped alert notification: " + bucket.Count.ToString(CultureInfo.InvariantCulture) +
                " related " + bucket.Category.ToLowerInvariant() + " alerts";
            string body = BuildSummaryBody(bucket);
            string recommendation = "Review the grouped local alerts if this source, destination set, or timing was unexpected. Arcane preserved each original alert locally; this notification only dampens external delivery for the burst.";
            Alert summary = Alert.SystemAlert(
                FirstNonEmpty(FirstTopKey(bucket.RuleCounts), "ALERT-GROUPED"),
                title,
                bucket.MaxScore,
                body,
                recommendation,
                BuildSummaryEntity(bucket));
            summary.Category = bucket.Category;
            summary.CooldownKey = GroupedCooldownPrefix + bucket.Key;
            summary.MaintenanceContext = bucket.AnyMaintenanceContext;
            summary.AddWhy("Grouped " + bucket.Count.ToString(CultureInfo.InvariantCulture) + " same-root external notifications into one deterministic summary.");
            summary.AddWhy("Local alert logs, incident grouping, and response handling were already preserved for each original alert.");
            summary.AddWhy("Highest grouped score: " + bucket.MaxScore.ToString(CultureInfo.InvariantCulture) + ".");
            return summary;
        }

        private string BuildSummaryBody(GroupBucket bucket)
        {
            StringBuilder builder = new StringBuilder();
            builder.AppendLine("Arcane grouped related external notifications from one dispatch.");
            builder.AppendLine("Grouped alert count: " + bucket.Count.ToString(CultureInfo.InvariantCulture));
            builder.AppendLine("Highest score: " + bucket.MaxScore.ToString(CultureInfo.InvariantCulture));
            builder.AppendLine("First observed UTC: " + bucket.FirstTimestampUtc.ToString("yyyy-MM-ddTHH:mm:ssZ", CultureInfo.InvariantCulture));
            builder.AppendLine("Last observed UTC: " + bucket.LastTimestampUtc.ToString("yyyy-MM-ddTHH:mm:ssZ", CultureInfo.InvariantCulture));
            builder.AppendLine();
            AppendCounts(builder, "Rules", bucket.RuleCounts, config.ExternalAlertGroupingMaxItems);
            AppendCounts(builder, "Titles", bucket.TitleCounts, config.ExternalAlertGroupingMaxItems);
            AppendCounts(builder, "Processes", bucket.ProcessCounts, config.ExternalAlertGroupingMaxItems);
            AppendCounts(builder, "Destinations", bucket.DestinationCounts, config.ExternalAlertGroupingMaxItems);
            AppendCounts(builder, "Countries", bucket.CountryCounts, config.ExternalAlertGroupingMaxItems);
            AppendCounts(builder, "Companies", bucket.CompanyCounts, config.ExternalAlertGroupingMaxItems);
            return builder.ToString().TrimEnd();
        }

        private static string BuildSummaryEntity(GroupBucket bucket)
        {
            return "grouped_alerts=" + bucket.Count.ToString(CultureInfo.InvariantCulture) +
                " grouped_category=" + TokenValue(bucket.Category) +
                " grouped_rules=" + TokenValue(JoinTopKeys(bucket.RuleCounts, 6)) +
                " process=" + TokenValue(FirstTopKey(bucket.ProcessCounts)) +
                " remote=" + TokenValue(JoinTopKeys(bucket.DestinationCounts, 6)) +
                " country=" + TokenValue(JoinTopKeys(bucket.CountryCounts, 6)) +
                " remote_owner=" + TokenValue(JoinTopKeys(bucket.CompanyCounts, 6)) +
                " enrichment_source=grouped-alert-notification";
        }

        private static void AppendCounts(StringBuilder builder, string label, Dictionary<string, int> counts, int maxItems)
        {
            if (counts == null || counts.Count == 0) return;

            builder.AppendLine(label + ":");
            List<KeyValuePair<string, int>> sorted = SortedCounts(counts);
            int emitted = 0;
            foreach (KeyValuePair<string, int> item in sorted)
            {
                if (emitted >= maxItems) break;
                builder.AppendLine("- " + item.Key + " (" + item.Value.ToString(CultureInfo.InvariantCulture) + ")");
                emitted++;
            }

            int remaining = sorted.Count - emitted;
            if (remaining > 0)
            {
                builder.AppendLine("- plus " + remaining.ToString(CultureInfo.InvariantCulture) + " more");
            }

            builder.AppendLine();
        }

        private static List<KeyValuePair<string, int>> SortedCounts(Dictionary<string, int> counts)
        {
            List<KeyValuePair<string, int>> sorted = new List<KeyValuePair<string, int>>(counts);
            sorted.Sort(delegate(KeyValuePair<string, int> left, KeyValuePair<string, int> right)
            {
                int count = right.Value.CompareTo(left.Value);
                return count != 0 ? count : String.Compare(left.Key, right.Key, StringComparison.OrdinalIgnoreCase);
            });

            return sorted;
        }

        private static string FirstTopKey(Dictionary<string, int> counts)
        {
            List<KeyValuePair<string, int>> sorted = SortedCounts(counts);
            return sorted.Count == 0 ? "" : sorted[0].Key;
        }

        private static string JoinTopKeys(Dictionary<string, int> counts, int maxItems)
        {
            if (counts == null || counts.Count == 0) return "";

            List<KeyValuePair<string, int>> sorted = SortedCounts(counts);
            List<string> values = new List<string>();
            for (int index = 0; index < sorted.Count && index < maxItems; index++)
            {
                values.Add(sorted[index].Key);
            }

            return String.Join(";", values.ToArray());
        }

        private static string Destination(Alert alert)
        {
            string entity = alert.EntitySummary ?? "";
            return FirstNonEmpty(
                ExtractToken(entity, "remote"),
                ExtractToken(entity, "remote_ip"),
                ExtractToken(entity, "resolved_domain"),
                ExtractToken(entity, "registrable_domain"),
                ExtractToken(entity, "sni_hostname"),
                ExtractToken(entity, "remote_host"),
                ExtractToken(entity, "query"),
                ExtractToken(entity, "target"),
                ExtractToken(entity, "name"),
                ExtractToken(entity, "path"),
                alert.Title);
        }

        private static string Company(Alert alert)
        {
            string entity = alert.EntitySummary ?? "";
            return FirstNonEmpty(
                ExtractToken(entity, "remote_owner"),
                ExtractToken(entity, "owner"),
                ExtractToken(entity, "asn_org"));
        }

        private static string Process(Alert alert)
        {
            string entity = alert.EntitySummary ?? "";
            return FirstNonEmpty(
                ExtractToken(entity, "process"),
                FileNameOrValue(ExtractToken(entity, "image")),
                FileNameOrValue(ExtractToken(entity, "process_path")),
                ExtractToken(entity, "host_application"),
                "unknown-process");
        }

        private static void Increment(Dictionary<string, int> counts, string value)
        {
            if (counts == null || String.IsNullOrWhiteSpace(value)) return;

            string clean = Compact(value, 180);
            if (String.IsNullOrWhiteSpace(clean) ||
                clean.Equals("unknown", StringComparison.OrdinalIgnoreCase) ||
                clean.Equals("n/a", StringComparison.OrdinalIgnoreCase))
            {
                return;
            }

            int existing;
            counts.TryGetValue(clean, out existing);
            counts[clean] = existing + 1;
        }

        private static string ExtractToken(string entity, string key)
        {
            if (String.IsNullOrWhiteSpace(entity) || String.IsNullOrWhiteSpace(key)) return "";

            string prefix = key + "=";
            int index = entity.IndexOf(prefix, StringComparison.OrdinalIgnoreCase);
            while (index > 0 && !Char.IsWhiteSpace(entity[index - 1]))
            {
                index = entity.IndexOf(prefix, index + prefix.Length, StringComparison.OrdinalIgnoreCase);
            }

            if (index < 0) return "";

            int start = index + prefix.Length;
            int end = FindNextEntityTokenStart(entity, start);
            if (end < 0) end = entity.Length;
            return entity.Substring(start, end - start).Trim().Trim('"');
        }

        private static int FindNextEntityTokenStart(string entity, int start)
        {
            if (String.IsNullOrWhiteSpace(entity) || start < 0 || start >= entity.Length) return -1;

            for (int index = start; index < entity.Length; index++)
            {
                if (!Char.IsWhiteSpace(entity[index])) continue;

                int candidate = index + 1;
                while (candidate < entity.Length && Char.IsWhiteSpace(entity[candidate]))
                {
                    candidate++;
                }

                if (candidate >= entity.Length) return -1;
                foreach (string key in EntityTokenKeys)
                {
                    if (HasEntityTokenPrefix(entity, candidate, key))
                    {
                        return index;
                    }
                }
            }

            return -1;
        }

        private static bool HasEntityTokenPrefix(string entity, int index, string key)
        {
            if (String.IsNullOrWhiteSpace(entity) || String.IsNullOrWhiteSpace(key)) return false;

            string prefix = key + "=";
            if (index < 0 || index + prefix.Length > entity.Length) return false;
            return String.Compare(entity, index, prefix, 0, prefix.Length, StringComparison.OrdinalIgnoreCase) == 0;
        }

        private static string FileNameOrValue(string value)
        {
            if (String.IsNullOrWhiteSpace(value)) return "";

            try
            {
                string fileName = Path.GetFileName(value);
                if (!String.IsNullOrWhiteSpace(fileName)) return fileName;
            }
            catch
            {
            }

            return value;
        }

        private static string FirstNonEmpty(params string[] values)
        {
            foreach (string value in values)
            {
                if (!String.IsNullOrWhiteSpace(value)) return value;
            }

            return "";
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

        private static string Compact(string value, int maxLength)
        {
            if (String.IsNullOrWhiteSpace(value)) return "";
            string compact = value.Replace("\r", " ").Replace("\n", " ").Trim();
            if (compact.Length <= maxLength) return compact;
            return compact.Substring(0, maxLength) + "...";
        }

        private static string TokenValue(string value)
        {
            if (String.IsNullOrWhiteSpace(value)) return "";
            return value.Trim()
                .Replace("\r", " ")
                .Replace("\n", " ");
        }

        private sealed class OrderedAlert
        {
            public readonly int Order;
            public readonly Alert Alert;

            public OrderedAlert(int order, Alert alert)
            {
                Order = order;
                Alert = alert;
            }
        }

        private sealed class GroupBucket
        {
            public readonly string Key;
            public readonly int FirstOrder;
            public readonly string Category;
            public readonly List<OrderedAlert> Alerts = new List<OrderedAlert>();
            public readonly Dictionary<string, int> RuleCounts = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
            public readonly Dictionary<string, int> TitleCounts = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
            public readonly Dictionary<string, int> ProcessCounts = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
            public readonly Dictionary<string, int> DestinationCounts = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
            public readonly Dictionary<string, int> CountryCounts = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
            public readonly Dictionary<string, int> CompanyCounts = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
            public int Count;
            public int MaxScore;
            public bool AnyMaintenanceContext;
            public DateTime FirstTimestampUtc = DateTime.MaxValue;
            public DateTime LastTimestampUtc = DateTime.MinValue;

            public GroupBucket(string key, int firstOrder, string category)
            {
                Key = key;
                FirstOrder = firstOrder;
                Category = String.IsNullOrWhiteSpace(category) ? AlertRuleTaxonomy.CategoryGeneral : category;
            }

            public void Add(Alert alert, int order)
            {
                Alerts.Add(new OrderedAlert(order, alert));
                Count++;
                if (alert.Score > MaxScore) MaxScore = alert.Score;
                if (alert.MaintenanceContext) AnyMaintenanceContext = true;
                if (alert.TimestampUtc < FirstTimestampUtc) FirstTimestampUtc = alert.TimestampUtc;
                if (alert.TimestampUtc > LastTimestampUtc) LastTimestampUtc = alert.TimestampUtc;
                Increment(RuleCounts, alert.RuleId);
                Increment(TitleCounts, alert.Title);
                Increment(ProcessCounts, Process(alert));
                Increment(DestinationCounts, Destination(alert));
                Increment(CountryCounts, ExtractToken(alert.EntitySummary ?? "", "country"));
                Increment(CompanyCounts, Company(alert));
            }
        }
    }
}
