using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Web.Script.Serialization;

namespace ArcaneEDR
{
    internal static class AgentActivityConsole
    {
        public static int PrintSummary(string baseDirectory, string[] args)
        {
            MonitorConfig config = MonitorConfig.Load(baseDirectory);
            TimeSpan lookback = InvestigationConsoleOptions.ParseLookback(args, TimeSpan.FromHours(24));
            bool json = HasFlag(args, "--json");

            if (!File.Exists(config.AgentActivityLedgerFile))
            {
                if (json)
                {
                    PrintJson(config, lookback, new List<AgentActivityRecord>(), false);
                    return 0;
                }

                Console.WriteLine("Agent activity from the last " + InvestigationConsoleOptions.Describe(lookback) + " using " + config.AgentActivityLedgerFile);
                Console.WriteLine("No agent activity ledger found.");
                return 0;
            }

            List<AgentActivityRecord> records = LoadRecords(config.AgentActivityLedgerFile, lookback);
            if (json)
            {
                PrintJson(config, lookback, records, true);
                return 0;
            }

            Console.WriteLine("Agent activity from the last " + InvestigationConsoleOptions.Describe(lookback) + " using " + config.AgentActivityLedgerFile);
            if (records.Count == 0)
            {
                Console.WriteLine("No agent activity records found.");
                return 0;
            }

            int maxScore = 0;
            int maintenance = 0;
            foreach (AgentActivityRecord record in records)
            {
                if (record.Score > maxScore) maxScore = record.Score;
                if (record.MaintenanceContext) maintenance++;
            }

            Console.WriteLine("TotalRecords=" + records.Count.ToString(CultureInfo.InvariantCulture) +
                " HighestScore=" + maxScore.ToString(CultureInfo.InvariantCulture) +
                " MaintenanceContext=" + maintenance.ToString(CultureInfo.InvariantCulture));
            Console.WriteLine("");

            PrintBuckets("By Rule", BuildBuckets(records, "rule"));
            PrintBuckets("By Command Category", BuildBuckets(records, "command"));
            PrintBuckets("By Endpoint Category", BuildBuckets(records, "endpoint"));
            PrintBuckets("By File Category", BuildBuckets(records, "file"));
            PrintBuckets("By Process Family", BuildBuckets(records, "process"));
            PrintRecent(records);

            return 0;
        }

        private static void PrintJson(MonitorConfig config, TimeSpan lookback, List<AgentActivityRecord> records, bool ledgerFound)
        {
            int maxScore = 0;
            int maintenance = 0;
            foreach (AgentActivityRecord record in records)
            {
                if (record.Score > maxScore) maxScore = record.Score;
                if (record.MaintenanceContext) maintenance++;
            }

            Dictionary<string, object> root = new Dictionary<string, object>();
            root["schema"] = "arcane.agent_activity.v1";
            root["ok"] = true;
            root["ledger_found"] = ledgerFound;
            root["ledger_file"] = config.AgentActivityLedgerFile;
            root["lookback"] = InvestigationConsoleOptions.Describe(lookback);
            root["total_records"] = records.Count;
            root["highest_score"] = maxScore;
            root["maintenance_context"] = maintenance;
            root["by_rule"] = Limit(BuildBuckets(records, "rule"), 30);
            root["by_command_category"] = Limit(BuildBuckets(records, "command"), 30);
            root["by_endpoint_category"] = Limit(BuildBuckets(records, "endpoint"), 30);
            root["by_file_category"] = Limit(BuildBuckets(records, "file"), 30);
            root["by_process_family"] = Limit(BuildBuckets(records, "process"), 30);
            root["recent"] = Limit(Recent(records), 20);
            Console.WriteLine(new JavaScriptSerializer().Serialize(root));
        }

        private static List<AgentActivityRecord> LoadRecords(string path, TimeSpan lookback)
        {
            List<AgentActivityRecord> result = new List<AgentActivityRecord>();
            DateTime cutoffUtc = DateTime.UtcNow.Subtract(lookback);
            JavaScriptSerializer serializer = new JavaScriptSerializer();

            foreach (string line in File.ReadAllLines(path))
            {
                AgentActivityRecord record = ParseRecord(serializer, line);
                if (record == null || record.TimestampUtc < cutoffUtc) continue;
                result.Add(record);
            }

            return result;
        }

        private static AgentActivityRecord ParseRecord(JavaScriptSerializer serializer, string line)
        {
            if (String.IsNullOrWhiteSpace(line)) return null;

            try
            {
                Dictionary<string, object> parsed = serializer.Deserialize<Dictionary<string, object>>(line);
                if (parsed == null) return null;

                DateTime timestampUtc;
                if (!UtcTimestamp.TryParse(JsonFields.ReadString(parsed, "timestamp_utc"), out timestampUtc)) return null;

                AgentActivityRecord record = new AgentActivityRecord();
                record.TimestampUtc = timestampUtc;
                record.RuleId = TextFormatting.UnknownIfBlank(JsonFields.ReadString(parsed, "rule_id"));
                record.Category = TextFormatting.UnknownIfBlank(JsonFields.ReadString(parsed, "category"));
                record.Severity = TextFormatting.UnknownIfBlank(JsonFields.ReadString(parsed, "severity"));
                record.Score = JsonFields.ReadInt(parsed, "score");
                record.MaintenanceContext = JsonFields.ReadBool(parsed, "maintenance_context");
                record.ProcessFamily = TextFormatting.UnknownIfBlank(JsonFields.ReadString(parsed, "process_family"));
                record.CommandCategory = TextFormatting.UnknownIfBlank(JsonFields.ReadString(parsed, "command_category"));
                record.EndpointCategory = TextFormatting.UnknownIfBlank(JsonFields.ReadString(parsed, "endpoint_category"));
                record.FileCategory = TextFormatting.UnknownIfBlank(JsonFields.ReadString(parsed, "file_category"));
                return record;
            }
            catch
            {
                return null;
            }
        }

        private static List<AgentActivityBucket> BuildBuckets(List<AgentActivityRecord> records, string field)
        {
            Dictionary<string, AgentActivityBucket> byName = new Dictionary<string, AgentActivityBucket>(StringComparer.OrdinalIgnoreCase);
            foreach (AgentActivityRecord record in records)
            {
                string name = BucketName(record, field);
                AgentActivityBucket bucket;
                if (!byName.TryGetValue(name, out bucket))
                {
                    bucket = new AgentActivityBucket();
                    bucket.Name = name;
                    byName[name] = bucket;
                }

                bucket.Count++;
                if (record.Score > bucket.MaxScore) bucket.MaxScore = record.Score;
                if (record.MaintenanceContext) bucket.MaintenanceContext++;
            }

            List<AgentActivityBucket> buckets = new List<AgentActivityBucket>(byName.Values);
            buckets.Sort(delegate(AgentActivityBucket left, AgentActivityBucket right)
            {
                int countComparison = right.Count.CompareTo(left.Count);
                if (countComparison != 0) return countComparison;
                int scoreComparison = right.MaxScore.CompareTo(left.MaxScore);
                if (scoreComparison != 0) return scoreComparison;
                return String.Compare(left.Name, right.Name, StringComparison.OrdinalIgnoreCase);
            });
            return buckets;
        }

        private static void PrintBuckets(string title, List<AgentActivityBucket> buckets)
        {
            Console.WriteLine(title);
            int limit = Math.Min(12, buckets.Count);
            for (int index = 0; index < limit; index++)
            {
                AgentActivityBucket bucket = buckets[index];
                Console.WriteLine("  " + bucket.Name +
                    " count=" + bucket.Count.ToString(CultureInfo.InvariantCulture) +
                    " max=" + bucket.MaxScore.ToString(CultureInfo.InvariantCulture) +
                    " maintenance_context=" + bucket.MaintenanceContext.ToString(CultureInfo.InvariantCulture));
            }

            if (buckets.Count > limit)
            {
                Console.WriteLine("  ... " + (buckets.Count - limit).ToString(CultureInfo.InvariantCulture) + " more");
            }

            Console.WriteLine("");
        }

        private static void PrintRecent(List<AgentActivityRecord> records)
        {
            Console.WriteLine("Recent");
            int start = Math.Max(0, records.Count - 20);
            for (int index = start; index < records.Count; index++)
            {
                AgentActivityRecord record = records[index];
                Console.WriteLine("  " + UtcTimestamp.Format(record.TimestampUtc) +
                    " score=" + record.Score.ToString(CultureInfo.InvariantCulture) +
                    " rule=" + record.RuleId +
                    " process=" + record.ProcessFamily +
                    " command=" + record.CommandCategory +
                    " endpoint=" + record.EndpointCategory +
                    " file=" + record.FileCategory +
                    " maintenance_context=" + record.MaintenanceContext);
            }

            Console.WriteLine("");
        }

        private static string BucketName(AgentActivityRecord record, string field)
        {
            if (field.Equals("rule", StringComparison.OrdinalIgnoreCase)) return record.RuleId;
            if (field.Equals("command", StringComparison.OrdinalIgnoreCase)) return record.CommandCategory;
            if (field.Equals("endpoint", StringComparison.OrdinalIgnoreCase)) return record.EndpointCategory;
            if (field.Equals("file", StringComparison.OrdinalIgnoreCase)) return record.FileCategory;
            if (field.Equals("process", StringComparison.OrdinalIgnoreCase)) return record.ProcessFamily;
            return "unknown";
        }

        private static List<AgentActivityRecord> Recent(List<AgentActivityRecord> records)
        {
            List<AgentActivityRecord> recent = new List<AgentActivityRecord>(records);
            recent.Sort(delegate(AgentActivityRecord left, AgentActivityRecord right)
            {
                return right.TimestampUtc.CompareTo(left.TimestampUtc);
            });
            return recent;
        }

        private static List<T> Limit<T>(List<T> values, int limit)
        {
            if (values.Count <= limit) return values;
            return values.GetRange(0, limit);
        }

        private static bool HasFlag(string[] args, string name)
        {
            if (args == null) return false;
            foreach (string arg in args)
            {
                if (arg.Equals(name, StringComparison.OrdinalIgnoreCase)) return true;
            }

            return false;
        }

    }

    internal sealed class AgentActivityRecord
    {
        public DateTime TimestampUtc;
        public string RuleId;
        public string Category;
        public string Severity;
        public int Score;
        public bool MaintenanceContext;
        public string ProcessFamily;
        public string CommandCategory;
        public string EndpointCategory;
        public string FileCategory;
    }

    internal sealed class AgentActivityBucket
    {
        public string Name;
        public int Count;
        public int MaxScore;
        public int MaintenanceContext;
    }
}
