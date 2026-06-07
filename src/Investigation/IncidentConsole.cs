using System;
using System.Collections.Generic;
using System.Globalization;

namespace ArcaneEDR
{
    internal static class IncidentConsole
    {
        public static int PrintIncidents(string baseDirectory, string[] args)
        {
            MonitorConfig config = MonitorConfig.Load(baseDirectory);
            IncidentStore store = new IncidentStore(config, null);
            TimeSpan lookback = ParseLookback(args, TimeSpan.FromHours(24));
            List<IncidentSummary> summaries = store.ListSummaries(lookback);

            Console.WriteLine("Incidents from the last " + Describe(lookback) + " using " + config.IncidentStoreFile);
            if (summaries.Count == 0)
            {
                Console.WriteLine("No incidents found.");
                return 0;
            }

            foreach (IncidentSummary summary in summaries)
            {
                Console.WriteLine(summary.IncidentId +
                    " last=" + IncidentStore.FormatUtc(summary.LastSeenUtc) +
                    " first=" + IncidentStore.FormatUtc(summary.FirstSeenUtc) +
                    " count=" + summary.AlertCount.ToString(CultureInfo.InvariantCulture) +
                    " max=" + summary.MaxScore.ToString(CultureInfo.InvariantCulture) +
                    " severity=" + NullToUnknown(summary.Severity) +
                    " category=" + NullToUnknown(summary.Category) +
                    " user=" + NullToUnknown(summary.User) +
                    " process=" + NullToUnknown(summary.Process));

                Console.WriteLine("  latest: " + NullToUnknown(summary.LatestTitle));
                Console.WriteLine("  rules: " + String.Join(",", summary.RuleIds.ToArray()));
                if (!String.IsNullOrWhiteSpace(summary.LatestRecommendation))
                {
                    Console.WriteLine("  recommendation: " + summary.LatestRecommendation);
                }
            }

            return 0;
        }

        public static int PrintTimeline(string baseDirectory, string incidentId)
        {
            if (String.IsNullOrWhiteSpace(incidentId))
            {
                Console.WriteLine("Usage: ArcaneEDR.exe --timeline <incident-id>");
                return 1;
            }

            MonitorConfig config = MonitorConfig.Load(baseDirectory);
            IncidentStore store = new IncidentStore(config, null);
            List<IncidentRecord> records = store.Timeline(incidentId);

            Console.WriteLine("Timeline for " + incidentId + " using " + config.IncidentStoreFile);
            if (records.Count == 0)
            {
                Console.WriteLine("No records found for that incident.");
                return 1;
            }

            foreach (IncidentRecord record in records)
            {
                Console.WriteLine(record.observed_utc +
                    " score=" + record.score.ToString(CultureInfo.InvariantCulture) +
                    " severity=" + NullToUnknown(record.severity) +
                    " rule=" + NullToUnknown(record.rule_id) +
                    " title=" + NullToUnknown(record.title));

                if (!String.IsNullOrWhiteSpace(record.why))
                {
                    Console.WriteLine("  why: " + record.why);
                }

                if (!String.IsNullOrWhiteSpace(record.entity))
                {
                    Console.WriteLine("  entity: " + record.entity);
                }

                if (!String.IsNullOrWhiteSpace(record.recommendation))
                {
                    Console.WriteLine("  recommendation: " + record.recommendation);
                }
            }

            return 0;
        }

        private static TimeSpan ParseLookback(string[] args, TimeSpan fallback)
        {
            for (int index = 0; args != null && index < args.Length - 1; index++)
            {
                if (args[index].Equals("--last", StringComparison.OrdinalIgnoreCase))
                {
                    TimeSpan parsed;
                    if (TryParseDuration(args[index + 1], out parsed)) return parsed;
                }
            }

            return fallback;
        }

        private static bool TryParseDuration(string value, out TimeSpan result)
        {
            result = TimeSpan.Zero;
            if (String.IsNullOrWhiteSpace(value)) return false;

            string trimmed = value.Trim().ToLowerInvariant();
            double number;
            if (trimmed.EndsWith("m", StringComparison.OrdinalIgnoreCase) &&
                Double.TryParse(trimmed.Substring(0, trimmed.Length - 1), NumberStyles.Float, CultureInfo.InvariantCulture, out number))
            {
                result = TimeSpan.FromMinutes(number);
                return number > 0;
            }

            if (trimmed.EndsWith("h", StringComparison.OrdinalIgnoreCase) &&
                Double.TryParse(trimmed.Substring(0, trimmed.Length - 1), NumberStyles.Float, CultureInfo.InvariantCulture, out number))
            {
                result = TimeSpan.FromHours(number);
                return number > 0;
            }

            if (trimmed.EndsWith("d", StringComparison.OrdinalIgnoreCase) &&
                Double.TryParse(trimmed.Substring(0, trimmed.Length - 1), NumberStyles.Float, CultureInfo.InvariantCulture, out number))
            {
                result = TimeSpan.FromDays(number);
                return number > 0;
            }

            return TimeSpan.TryParse(value, out result) && result > TimeSpan.Zero;
        }

        private static string Describe(TimeSpan value)
        {
            if (value.TotalDays >= 1 && value.TotalDays == Math.Floor(value.TotalDays))
            {
                return value.TotalDays.ToString("0", CultureInfo.InvariantCulture) + "d";
            }

            if (value.TotalHours >= 1 && value.TotalHours == Math.Floor(value.TotalHours))
            {
                return value.TotalHours.ToString("0", CultureInfo.InvariantCulture) + "h";
            }

            return value.TotalMinutes.ToString("0", CultureInfo.InvariantCulture) + "m";
        }

        private static string NullToUnknown(string value)
        {
            return String.IsNullOrWhiteSpace(value) ? "unknown" : value;
        }
    }
}
