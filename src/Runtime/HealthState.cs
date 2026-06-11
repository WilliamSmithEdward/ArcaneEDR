using System;
using System.Globalization;
using System.IO;

namespace ArcaneEDR
{
    internal sealed class HealthState
    {
        public DateTime? LastStartUtc;
        public DateTime? LastCleanStopUtc;
        public DateTime? LastHeartbeatUtc;
        public DateTime? LastDailySummaryUtc;
        public DateTime? LastAIAnalysisUtc;
        public string LastRunId;
        public bool Running;
        public long PollCount;
        public long AlertCount;
        public long ExternalSendFailures;
        public long PollFailures;

        public static HealthState Load(string path)
        {
            HealthState state = new HealthState();
            if (!File.Exists(path)) return state;

            foreach (string line in File.ReadAllLines(path))
            {
                int equals = line.IndexOf('=');
                if (equals <= 0) continue;

                string key = line.Substring(0, equals);
                string value = line.Substring(equals + 1);
                if (key == "LastStartUtc") state.LastStartUtc = ReadDate(value);
                else if (key == "LastCleanStopUtc") state.LastCleanStopUtc = ReadDate(value);
                else if (key == "LastHeartbeatUtc") state.LastHeartbeatUtc = ReadDate(value);
                else if (key == "LastDailySummaryUtc") state.LastDailySummaryUtc = ReadDate(value);
                else if (key == "LastAIAnalysisUtc") state.LastAIAnalysisUtc = ReadDate(value);
                else if (key == "LastRunId") state.LastRunId = value;
                else if (key == "Running") state.Running = value.Equals("true", StringComparison.OrdinalIgnoreCase);
                else if (key == "PollCount") state.PollCount = ReadLong(value);
                else if (key == "AlertCount") state.AlertCount = ReadLong(value);
                else if (key == "ExternalSendFailures") state.ExternalSendFailures = ReadLong(value);
                else if (key == "PollFailures") state.PollFailures = ReadLong(value);
            }

            return state;
        }

        public void Save(string path)
        {
            Directory.CreateDirectory(Path.GetDirectoryName(path));
            string[] lines = new string[]
            {
                "LastStartUtc=" + UtcTimestamp.Format(LastStartUtc),
                "LastCleanStopUtc=" + UtcTimestamp.Format(LastCleanStopUtc),
                "LastHeartbeatUtc=" + UtcTimestamp.Format(LastHeartbeatUtc),
                "LastDailySummaryUtc=" + UtcTimestamp.Format(LastDailySummaryUtc),
                "LastAIAnalysisUtc=" + UtcTimestamp.Format(LastAIAnalysisUtc),
                "LastRunId=" + (LastRunId ?? ""),
                "Running=" + (Running ? "true" : "false"),
                "PollCount=" + PollCount.ToString(CultureInfo.InvariantCulture),
                "AlertCount=" + AlertCount.ToString(CultureInfo.InvariantCulture),
                "ExternalSendFailures=" + ExternalSendFailures.ToString(CultureInfo.InvariantCulture),
                "PollFailures=" + PollFailures.ToString(CultureInfo.InvariantCulture)
            };
            File.WriteAllLines(path, lines);
        }

        private static DateTime? ReadDate(string value)
        {
            if (String.IsNullOrWhiteSpace(value)) return null;
            DateTime parsed;
            return UtcTimestamp.TryParse(value, out parsed) ? parsed : (DateTime?)null;
        }

        private static long ReadLong(string value)
        {
            long parsed;
            return Int64.TryParse(value, out parsed) ? parsed : 0;
        }
    }
}
