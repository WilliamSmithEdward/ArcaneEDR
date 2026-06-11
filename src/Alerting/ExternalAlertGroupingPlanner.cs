using System;
using System.Collections.Generic;
using System.Globalization;
using System.Text;

namespace ArcaneEDR
{
    internal sealed class ExternalAlertGroupingPlanner
    {
        private readonly MonitorConfig config;

        public ExternalAlertGroupingPlanner(MonitorConfig config)
        {
            this.config = config;
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

                string key = IsGroupingCandidate(alert) ? AlertSourceRoot.BuildGroupingKey(alert) : "";
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

        private Alert BuildSummary(GroupBucket bucket)
        {
            string title = "Grouped alert notification: " + bucket.Count.ToString(CultureInfo.InvariantCulture) +
                " related " + bucket.Category.ToLowerInvariant() + " alerts";
            string body = BuildSummaryBody(bucket);
            string recommendation = "Review the grouped local alerts if this source, destination set, or timing was unexpected. Arcane preserved each original alert locally; this notification only dampens external delivery for the burst.";
            Alert summary = Alert.SystemAlert(
                AlertEntityTokens.FirstNonEmpty(FirstTopKey(bucket.RuleCounts), "ALERT-GROUPED"),
                title,
                bucket.MaxScore,
                body,
                recommendation,
                BuildSummaryEntity(bucket));
            summary.Category = bucket.Category;
            summary.CooldownKey = AlertSourceRoot.GroupedCooldownPrefix + bucket.Key;
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
            builder.AppendLine("First observed UTC: " + UtcTimestamp.Format(bucket.FirstTimestampUtc));
            builder.AppendLine("Last observed UTC: " + UtcTimestamp.Format(bucket.LastTimestampUtc));
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

        private static void Increment(Dictionary<string, int> counts, string value)
        {
            if (counts == null || String.IsNullOrWhiteSpace(value)) return;

            string clean = TextFormatting.CompactOrEmpty(value, 180);
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
                Increment(ProcessCounts, AlertSourceRoot.Process(alert));
                Increment(DestinationCounts, AlertSourceRoot.Destination(alert));
                Increment(CountryCounts, AlertEntityTokens.Get(alert.EntitySummary ?? "", "country"));
                Increment(CompanyCounts, AlertSourceRoot.Company(alert));
            }
        }
    }
}
