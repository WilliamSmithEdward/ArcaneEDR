using System;
using System.Collections.Generic;
using System.Globalization;
using System.Web.Script.Serialization;

namespace ArcaneEDR
{
    internal static class IncidentConsole
    {
        public static int PrintIncidents(string baseDirectory, string[] args)
        {
            MonitorConfig config = MonitorConfig.Load(baseDirectory);
            IncidentStore store = new IncidentStore(config, null);
            TimeSpan lookback = InvestigationConsoleOptions.ParseLookback(args, TimeSpan.FromHours(24));
            List<IncidentSummary> summaries = store.ListSummaries(lookback);
            bool json = HasFlag(args, "--json");

            if (json)
            {
                Dictionary<string, object> root = new Dictionary<string, object>();
                root["schema"] = "arcane.incidents.v1";
                root["ok"] = true;
                root["incident_store_file"] = config.IncidentStoreFile;
                root["lookback"] = InvestigationConsoleOptions.Describe(lookback);
                root["total_incidents"] = summaries.Count;
                root["incidents"] = summaries;
                Console.WriteLine(new JavaScriptSerializer().Serialize(root));
                return 0;
            }

            Console.WriteLine("Incidents from the last " + InvestigationConsoleOptions.Describe(lookback) + " using " + config.IncidentStoreFile);
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
                    " severity=" + TextFormatting.UnknownIfBlank(summary.Severity) +
                    " category=" + TextFormatting.UnknownIfBlank(summary.Category) +
                    " maintenance_context=" + summary.HasMaintenanceContext +
                    " user=" + TextFormatting.UnknownIfBlank(summary.User) +
                    " process=" + TextFormatting.UnknownIfBlank(summary.Process));

                Console.WriteLine("  latest: " + TextFormatting.UnknownIfBlank(summary.LatestTitle));
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
                    " severity=" + TextFormatting.UnknownIfBlank(record.severity) +
                    " rule=" + TextFormatting.UnknownIfBlank(record.rule_id) +
                    " maintenance_context=" + record.maintenance_context +
                    " title=" + TextFormatting.UnknownIfBlank(record.title));

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
}
