using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Web.Script.Serialization;

namespace ArcaneEDR
{
    internal static class AlertVolumeConsole
    {
        public static int PrintSummary(string baseDirectory, string[] args)
        {
            MonitorConfig config = MonitorConfig.Load(baseDirectory);
            TimeSpan lookback = InvestigationConsoleOptions.ParseLookback(args, TimeSpan.FromHours(24));
            string alertsPath = Path.Combine(config.LogDirectory, "ArcaneAlerts.jsonl");

            Console.WriteLine("Alert volume from the last " + InvestigationConsoleOptions.Describe(lookback) + " using " + alertsPath);
            if (!File.Exists(alertsPath))
            {
                Console.WriteLine("No alert log found.");
                return 0;
            }

            List<AlertVolumeRecord> records = LoadRecords(alertsPath, lookback, config);
            if (records.Count == 0)
            {
                Console.WriteLine("No alerts found.");
                return 0;
            }

            int externalQualified = 0;
            int baselineOffExternalQualified = 0;
            int maintenanceContext = 0;
            int maxScore = 0;
            foreach (AlertVolumeRecord record in records)
            {
                if (record.ExternalQualified) externalQualified++;
                if (record.BaselineOffExternalQualified) baselineOffExternalQualified++;
                if (record.MaintenanceContext) maintenanceContext++;
                if (record.Score > maxScore) maxScore = record.Score;
            }

            Console.WriteLine("TotalAlerts=" + records.Count.ToString(CultureInfo.InvariantCulture) +
                " ExternalQualifiedBeforeRateLimits=" + externalQualified.ToString(CultureInfo.InvariantCulture) +
                " BaselineOffExternalQualifiedBeforeRateLimits=" + baselineOffExternalQualified.ToString(CultureInfo.InvariantCulture) +
                " MaintenanceContext=" + maintenanceContext.ToString(CultureInfo.InvariantCulture) +
                " HighestScore=" + maxScore.ToString(CultureInfo.InvariantCulture));
            if (config.BaselineLearningMode)
            {
                Console.WriteLine("BaselineOffExternalQualifiedBeforeRateLimits is a dry-run projection; live config still has BaselineLearningMode=true.");
            }

            Console.WriteLine("");

            List<AlertVolumeBucket> severityBuckets = BuildBuckets(records, "severity");
            List<AlertVolumeBucket> categoryBuckets = BuildBuckets(records, "category");
            List<AlertVolumeBucket> ruleBuckets = BuildBuckets(records, "rule");
            List<AlertVolumeBucket> processBuckets = BuildBuckets(records, "process");

            if (baselineOffExternalQualified > externalQualified)
            {
                PrintBaselineOffDrivers("Baseline-Off Projection Drivers By Rule", ruleBuckets);
                PrintBaselineOffDrivers("Baseline-Off Projection Drivers By Process", processBuckets);
                PrintCandidateExamples("New Baseline-Off External Candidate Examples", records, true);
            }

            PrintCandidateExamples("Current External-Qualified Examples", records, false);

            PrintBuckets("By Severity", severityBuckets);
            PrintBuckets("By Category", categoryBuckets);
            PrintBuckets("By Rule", ruleBuckets);
            PrintBuckets("By Process", processBuckets);

            return 0;
        }

        private static List<AlertVolumeRecord> LoadRecords(string path, TimeSpan lookback, MonitorConfig config)
        {
            List<AlertVolumeRecord> result = new List<AlertVolumeRecord>();
            DateTime cutoffUtc = DateTime.UtcNow.Subtract(lookback);
            JavaScriptSerializer serializer = new JavaScriptSerializer();

            foreach (string line in File.ReadAllLines(path))
            {
                AlertVolumeRecord record = ParseRecord(serializer, line, config);
                if (record == null || record.TimestampUtc < cutoffUtc) continue;
                result.Add(record);
            }

            return result;
        }

        private static AlertVolumeRecord ParseRecord(JavaScriptSerializer serializer, string line, MonitorConfig config)
        {
            if (String.IsNullOrWhiteSpace(line)) return null;

            try
            {
                Dictionary<string, object> parsed = serializer.Deserialize<Dictionary<string, object>>(line);
                if (parsed == null) return null;

                Alert alert = new Alert();
                alert.RuleId = JsonFields.ReadString(parsed, "rule_id");
                alert.Category = JsonFields.ReadString(parsed, "category");
                alert.Severity = JsonFields.ReadString(parsed, "severity");
                alert.Score = JsonFields.ReadInt(parsed, "score");
                alert.Title = JsonFields.ReadString(parsed, "title");
                alert.Body = JsonFields.ReadString(parsed, "body");
                alert.EntitySummary = JsonFields.ReadString(parsed, "entity");
                alert.MaintenanceContext = JsonFields.ReadBool(parsed, "maintenance_context");
                alert.ExternalSuppressedByPolicy = JsonFields.ReadBool(parsed, "external_suppressed_by_policy");
                alert.ExternalForcedByPolicy = JsonFields.ReadBool(parsed, "external_forced_by_policy");
                alert.PolicyContext = JsonFields.ReadString(parsed, "policy_context");

                DateTime timestampUtc;
                if (!UtcTimestamp.TryParse(JsonFields.ReadString(parsed, "timestamp_utc"), out timestampUtc))
                {
                    return null;
                }

                if (String.IsNullOrWhiteSpace(alert.Category))
                {
                    alert.Category = AlertRuleCatalog.CategoryFor(alert.RuleId);
                }

                if (String.IsNullOrWhiteSpace(alert.Severity))
                {
                    alert.Severity = AlertSeverity.FromScore(alert.Score);
                }

                AlertVolumeRecord record = new AlertVolumeRecord();
                record.TimestampUtc = timestampUtc;
                record.RuleId = TextFormatting.UnknownIfBlank(alert.RuleId);
                record.Category = TextFormatting.UnknownIfBlank(alert.Category);
                record.Severity = TextFormatting.UnknownIfBlank(alert.Severity);
                record.Score = alert.Score;
                record.Title = TextFormatting.UnknownIfBlank(alert.Title);
                record.Process = AlertEntityTokens.Get(alert.EntitySummary, "process");
                if (String.IsNullOrWhiteSpace(record.Process)) record.Process = "unknown";
                record.SystemLocalTime = JsonFields.ReadString(parsed, "system_local_time");
                record.MaintenanceContext = alert.MaintenanceContext;
                record.ExternalQualified = WouldQualifyForExternal(config, alert, false);
                record.BaselineOffExternalQualified = WouldQualifyForExternal(config, alert, true);
                return record;
            }
            catch
            {
                return null;
            }
        }

        private static bool WouldQualifyForExternal(MonitorConfig config, Alert alert, bool assumeBaselineLearningOff)
        {
            return ExternalAlertEligibility.WouldQualifyBeforeRateLimits(
                config,
                alert,
                assumeBaselineLearningOff,
                true);
        }

        private static List<AlertVolumeBucket> BuildBuckets(List<AlertVolumeRecord> records, string field)
        {
            Dictionary<string, AlertVolumeBucket> byName = new Dictionary<string, AlertVolumeBucket>(StringComparer.OrdinalIgnoreCase);
            foreach (AlertVolumeRecord record in records)
            {
                string name = BucketName(record, field);
                AlertVolumeBucket bucket;
                if (!byName.TryGetValue(name, out bucket))
                {
                    bucket = new AlertVolumeBucket();
                    bucket.Name = name;
                    byName[name] = bucket;
                }

                bucket.Count++;
                if (record.Score > bucket.MaxScore) bucket.MaxScore = record.Score;
                if (record.ExternalQualified) bucket.ExternalQualified++;
                if (record.BaselineOffExternalQualified) bucket.BaselineOffExternalQualified++;
                if (record.MaintenanceContext) bucket.MaintenanceContext++;
            }

            List<AlertVolumeBucket> buckets = new List<AlertVolumeBucket>(byName.Values);
            buckets.Sort(delegate(AlertVolumeBucket left, AlertVolumeBucket right)
            {
                int countComparison = right.Count.CompareTo(left.Count);
                if (countComparison != 0) return countComparison;
                int scoreComparison = right.MaxScore.CompareTo(left.MaxScore);
                if (scoreComparison != 0) return scoreComparison;
                return String.Compare(left.Name, right.Name, StringComparison.OrdinalIgnoreCase);
            });
            return buckets;
        }

        private static void PrintBuckets(string title, List<AlertVolumeBucket> buckets)
        {
            Console.WriteLine(title);
            int limit = Math.Min(12, buckets.Count);
            for (int index = 0; index < limit; index++)
            {
                AlertVolumeBucket bucket = buckets[index];
                Console.WriteLine("  " + bucket.Name +
                    " count=" + bucket.Count.ToString(CultureInfo.InvariantCulture) +
                    " max=" + bucket.MaxScore.ToString(CultureInfo.InvariantCulture) +
                    " external_qualified=" + bucket.ExternalQualified.ToString(CultureInfo.InvariantCulture) +
                    " baseline_off_external=" + bucket.BaselineOffExternalQualified.ToString(CultureInfo.InvariantCulture) +
                    " maintenance_context=" + bucket.MaintenanceContext.ToString(CultureInfo.InvariantCulture));
            }

            if (buckets.Count > limit)
            {
                Console.WriteLine("  ... " + (buckets.Count - limit).ToString(CultureInfo.InvariantCulture) + " more");
            }

            Console.WriteLine("");
        }

        private static void PrintBaselineOffDrivers(string title, List<AlertVolumeBucket> buckets)
        {
            List<AlertVolumeBucket> drivers = new List<AlertVolumeBucket>();
            foreach (AlertVolumeBucket bucket in buckets)
            {
                if (bucket.BaselineOffExternalQualified > bucket.ExternalQualified)
                {
                    drivers.Add(bucket);
                }
            }

            if (drivers.Count == 0) return;

            drivers.Sort(delegate(AlertVolumeBucket left, AlertVolumeBucket right)
            {
                int leftDelta = left.BaselineOffExternalQualified - left.ExternalQualified;
                int rightDelta = right.BaselineOffExternalQualified - right.ExternalQualified;
                int deltaComparison = rightDelta.CompareTo(leftDelta);
                if (deltaComparison != 0) return deltaComparison;
                int scoreComparison = right.MaxScore.CompareTo(left.MaxScore);
                if (scoreComparison != 0) return scoreComparison;
                return String.Compare(left.Name, right.Name, StringComparison.OrdinalIgnoreCase);
            });

            Console.WriteLine(title);
            int limit = Math.Min(8, drivers.Count);
            for (int index = 0; index < limit; index++)
            {
                AlertVolumeBucket bucket = drivers[index];
                int newlyQualified = bucket.BaselineOffExternalQualified - bucket.ExternalQualified;
                Console.WriteLine("  " + bucket.Name +
                    " newly_qualified=" + newlyQualified.ToString(CultureInfo.InvariantCulture) +
                    " baseline_off_external=" + bucket.BaselineOffExternalQualified.ToString(CultureInfo.InvariantCulture) +
                    " current_external=" + bucket.ExternalQualified.ToString(CultureInfo.InvariantCulture) +
                    " max=" + bucket.MaxScore.ToString(CultureInfo.InvariantCulture) +
                    " count=" + bucket.Count.ToString(CultureInfo.InvariantCulture));
            }

            if (drivers.Count > limit)
            {
                Console.WriteLine("  ... " + (drivers.Count - limit).ToString(CultureInfo.InvariantCulture) + " more");
            }

            Console.WriteLine("");
        }

        private static void PrintCandidateExamples(string title, List<AlertVolumeRecord> records, bool newlyQualifiedOnly)
        {
            List<AlertVolumeRecord> candidates = new List<AlertVolumeRecord>();
            foreach (AlertVolumeRecord record in records)
            {
                bool include = newlyQualifiedOnly
                    ? record.BaselineOffExternalQualified && !record.ExternalQualified
                    : record.ExternalQualified;
                if (include) candidates.Add(record);
            }

            if (candidates.Count == 0) return;

            candidates.Sort(delegate(AlertVolumeRecord left, AlertVolumeRecord right)
            {
                int timeComparison = right.TimestampUtc.CompareTo(left.TimestampUtc);
                if (timeComparison != 0) return timeComparison;
                int scoreComparison = right.Score.CompareTo(left.Score);
                if (scoreComparison != 0) return scoreComparison;
                return String.Compare(left.RuleId, right.RuleId, StringComparison.OrdinalIgnoreCase);
            });

            Console.WriteLine(title);
            int limit = Math.Min(8, candidates.Count);
            for (int index = 0; index < limit; index++)
            {
                AlertVolumeRecord record = candidates[index];
                Console.WriteLine("  " + FormatRecordTime(record) +
                    " score=" + record.Score.ToString(CultureInfo.InvariantCulture) +
                    " rule=" + record.RuleId +
                    " process=" + InvestigationConsoleOptions.CompactForConsole(record.Process, 48) +
                    " maintenance_context=" + (record.MaintenanceContext ? "true" : "false") +
                    " title=" + InvestigationConsoleOptions.CompactForConsole(record.Title, 96));
            }

            if (candidates.Count > limit)
            {
                Console.WriteLine("  ... " + (candidates.Count - limit).ToString(CultureInfo.InvariantCulture) + " more");
            }

            Console.WriteLine("");
        }

        private static string BucketName(AlertVolumeRecord record, string field)
        {
            if (field.Equals("severity", StringComparison.OrdinalIgnoreCase)) return record.Severity;
            if (field.Equals("category", StringComparison.OrdinalIgnoreCase)) return record.Category;
            if (field.Equals("rule", StringComparison.OrdinalIgnoreCase)) return record.RuleId;
            if (field.Equals("process", StringComparison.OrdinalIgnoreCase)) return record.Process;
            return "unknown";
        }

        private static string FormatRecordTime(AlertVolumeRecord record)
        {
            if (record != null && !String.IsNullOrWhiteSpace(record.SystemLocalTime))
            {
                return InvestigationConsoleOptions.CompactForConsole(record.SystemLocalTime, 64);
            }

            if (record == null) return "unknown-time";
            return UtcTimestamp.Format(record.TimestampUtc);
        }

    }

    internal sealed class AlertVolumeRecord
    {
        public DateTime TimestampUtc;
        public string RuleId;
        public string Category;
        public string Severity;
        public int Score;
        public string Title;
        public string Process;
        public string SystemLocalTime;
        public bool MaintenanceContext;
        public bool ExternalQualified;
        public bool BaselineOffExternalQualified;
    }

    internal sealed class AlertVolumeBucket
    {
        public string Name;
        public int Count;
        public int MaxScore;
        public int ExternalQualified;
        public int BaselineOffExternalQualified;
        public int MaintenanceContext;
    }
}
