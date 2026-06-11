using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Text;
using System.Web.Script.Serialization;

namespace ArcaneEDR
{
    internal sealed class MaintenanceSessionMarkerStore
    {
        private readonly MonitorConfig config;
        private readonly FileLogger logger;
        private readonly object gate = new object();

        public MaintenanceSessionMarkerStore(MonitorConfig config, FileLogger logger)
        {
            this.config = config;
            this.logger = logger;
        }

        public MaintenanceSessionMarker Start(TimeSpan requestedDuration, string reason, string source)
        {
            DateTime nowUtc = DateTime.UtcNow;
            TimeSpan duration = ClampDuration(requestedDuration);
            MaintenanceSessionMarker marker = new MaintenanceSessionMarker
            {
                TimestampUtc = nowUtc,
                StartUtc = nowUtc,
                EndUtc = nowUtc.Add(duration),
                DurationMinutes = (int)Math.Ceiling(duration.TotalMinutes),
                Reason = NormalizeLabel(reason, "manual"),
                Source = NormalizeLabel(source, "cli"),
                Cleared = false
            };

            Append(marker.ToJson());
            return marker;
        }

        public MaintenanceSessionMarker Clear(string reason, string source)
        {
            DateTime nowUtc = DateTime.UtcNow;
            MaintenanceSessionMarker marker = new MaintenanceSessionMarker
            {
                TimestampUtc = nowUtc,
                StartUtc = nowUtc,
                EndUtc = nowUtc,
                DurationMinutes = 0,
                Reason = NormalizeLabel(reason, "manual-clear"),
                Source = NormalizeLabel(source, "cli"),
                Cleared = true
            };

            Append(marker.ToJson());
            return marker;
        }

        public MaintenanceSessionMarker FindActive(DateTime timestampUtc)
        {
            if (config == null ||
                !config.EnableMaintenanceContext ||
                !config.EnableMaintenanceSessionMarkers ||
                String.IsNullOrWhiteSpace(config.MaintenanceSessionMarkerFile))
            {
                return null;
            }

            DateTime targetUtc = timestampUtc == DateTime.MinValue
                ? DateTime.UtcNow
                : timestampUtc.ToUniversalTime();
            MaintenanceSessionMarker active = null;

            foreach (MaintenanceSessionMarker marker in ReadAll())
            {
                if (marker.TimestampUtc > targetUtc) continue;
                if (marker.Cleared)
                {
                    active = null;
                    continue;
                }

                if (marker.StartUtc <= targetUtc && marker.EndUtc >= targetUtc)
                {
                    active = marker;
                }
            }

            return active;
        }

        public List<MaintenanceSessionMarker> Recent(TimeSpan lookback)
        {
            DateTime cutoffUtc = DateTime.UtcNow.Subtract(lookback);
            List<MaintenanceSessionMarker> records = new List<MaintenanceSessionMarker>();
            foreach (MaintenanceSessionMarker marker in ReadAll())
            {
                if (marker.TimestampUtc >= cutoffUtc) records.Add(marker);
            }

            return records;
        }

        private List<MaintenanceSessionMarker> ReadAll()
        {
            List<MaintenanceSessionMarker> records = new List<MaintenanceSessionMarker>();
            if (config == null || String.IsNullOrWhiteSpace(config.MaintenanceSessionMarkerFile)) return records;

            try
            {
                if (!File.Exists(config.MaintenanceSessionMarkerFile)) return records;
                JavaScriptSerializer serializer = new JavaScriptSerializer();
                foreach (string line in File.ReadAllLines(config.MaintenanceSessionMarkerFile))
                {
                    MaintenanceSessionMarker marker = Parse(serializer, line);
                    if (marker != null) records.Add(marker);
                }
            }
            catch (Exception ex)
            {
                if (logger != null)
                {
                    logger.Warn("Maintenance session marker read failed: " + ex.Message);
                }
            }

            return records;
        }

        private MaintenanceSessionMarker Parse(JavaScriptSerializer serializer, string line)
        {
            if (String.IsNullOrWhiteSpace(line)) return null;

            try
            {
                Dictionary<string, object> parsed = serializer.Deserialize<Dictionary<string, object>>(line);
                if (parsed == null) return null;

                DateTime timestampUtc;
                DateTime startUtc;
                DateTime endUtc;
                if (!UtcTimestamp.TryParse(JsonFields.ReadString(parsed, "timestamp_utc"), out timestampUtc)) return null;
                if (!UtcTimestamp.TryParse(JsonFields.ReadString(parsed, "start_utc"), out startUtc)) startUtc = timestampUtc;
                if (!UtcTimestamp.TryParse(JsonFields.ReadString(parsed, "end_utc"), out endUtc)) endUtc = timestampUtc;

                return new MaintenanceSessionMarker
                {
                    TimestampUtc = timestampUtc,
                    StartUtc = startUtc,
                    EndUtc = endUtc,
                    DurationMinutes = JsonFields.ReadInt(parsed, "duration_minutes"),
                    Reason = NormalizeLabel(JsonFields.ReadString(parsed, "reason"), "manual"),
                    Source = NormalizeLabel(JsonFields.ReadString(parsed, "source"), "cli"),
                    Cleared = JsonFields.ReadBool(parsed, "cleared")
                };
            }
            catch
            {
                return null;
            }
        }

        private void Append(string line)
        {
            if (config == null || String.IsNullOrWhiteSpace(config.MaintenanceSessionMarkerFile)) return;

            lock (gate)
            {
                string directory = Path.GetDirectoryName(config.MaintenanceSessionMarkerFile);
                if (!String.IsNullOrWhiteSpace(directory)) Directory.CreateDirectory(directory);
                LogFileRotation.RotateIfNeeded(config.MaintenanceSessionMarkerFile, config.MaxLogFileBytes);
                File.AppendAllText(config.MaintenanceSessionMarkerFile, line + Environment.NewLine);
            }
        }

        private TimeSpan ClampDuration(TimeSpan requestedDuration)
        {
            int defaultMinutes = config == null || config.MaintenanceSessionDefaultMinutes <= 0
                ? 60
                : config.MaintenanceSessionDefaultMinutes;
            int maximumMinutes = config == null || config.MaintenanceSessionMaximumMinutes <= 0
                ? 240
                : config.MaintenanceSessionMaximumMinutes;

            TimeSpan duration = requestedDuration > TimeSpan.Zero
                ? requestedDuration
                : TimeSpan.FromMinutes(defaultMinutes);
            TimeSpan maximum = TimeSpan.FromMinutes(maximumMinutes);
            return duration > maximum ? maximum : duration;
        }

        public static string NormalizeLabel(string value, string fallback)
        {
            string source = String.IsNullOrWhiteSpace(value) ? fallback : value.Trim();
            StringBuilder builder = new StringBuilder();
            foreach (char c in source)
            {
                if (Char.IsLetterOrDigit(c) || c == '-' || c == '_' || c == '.')
                {
                    builder.Append(Char.ToLowerInvariant(c));
                }
                else if (Char.IsWhiteSpace(c))
                {
                    builder.Append('_');
                }
            }

            string normalized = builder.ToString().Trim('_');
            if (String.IsNullOrWhiteSpace(normalized)) normalized = fallback;
            if (normalized.Length <= 80) return normalized;
            return normalized.Substring(0, 80);
        }

    }

    internal sealed class MaintenanceSessionMarker
    {
        public DateTime TimestampUtc;
        public DateTime StartUtc;
        public DateTime EndUtc;
        public int DurationMinutes;
        public string Reason;
        public string Source;
        public bool Cleared;

        public string AnnotationSummary(DateTime timestampUtc)
        {
            int remainingMinutes = Math.Max(0, (int)Math.Ceiling((EndUtc - timestampUtc.ToUniversalTime()).TotalMinutes));
            return "active_session reason=" + Safe(Reason) +
                " remaining_minutes=" + remainingMinutes.ToString(CultureInfo.InvariantCulture) +
                " until_utc=" + UtcTimestamp.Format(EndUtc);
        }

        public string ToJson()
        {
            return "{" +
                "\"timestamp_utc\":\"" + JsonFields.Escape(UtcTimestamp.Format(TimestampUtc)) + "\"," +
                "\"start_utc\":\"" + JsonFields.Escape(UtcTimestamp.Format(StartUtc)) + "\"," +
                "\"end_utc\":\"" + JsonFields.Escape(UtcTimestamp.Format(EndUtc)) + "\"," +
                "\"duration_minutes\":" + DurationMinutes.ToString(CultureInfo.InvariantCulture) + "," +
                "\"reason\":\"" + JsonFields.Escape(Safe(Reason)) + "\"," +
                "\"source\":\"" + JsonFields.Escape(Safe(Source)) + "\"," +
                "\"cleared\":" + (Cleared ? "true" : "false") +
                "}";
        }

        private static string Safe(string value)
        {
            return String.IsNullOrWhiteSpace(value) ? "manual" : value;
        }

    }
}
