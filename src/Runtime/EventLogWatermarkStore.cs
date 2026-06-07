using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;

namespace ArcaneEDR
{
    internal sealed class EventLogWatermark
    {
        public long RecordId;
        public DateTime TimestampUtc;
    }

    internal sealed class EventLogWatermarkStore
    {
        private readonly MonitorConfig config;
        private readonly FileLogger logger;
        private readonly Dictionary<string, EventLogWatermark> watermarks = new Dictionary<string, EventLogWatermark>(StringComparer.OrdinalIgnoreCase);
        private readonly object gate = new object();
        private bool loaded;
        private bool warnedLoad;
        private bool warnedSave;

        public EventLogWatermarkStore(MonitorConfig config, FileLogger logger)
        {
            this.config = config;
            this.logger = logger;
        }

        public EventLogWatermark Get(string logName)
        {
            if (!Enabled || String.IsNullOrWhiteSpace(logName)) return Empty();

            EnsureLoaded();
            lock (gate)
            {
                EventLogWatermark watermark;
                if (!watermarks.TryGetValue(logName, out watermark)) return Empty();
                return Copy(watermark);
            }
        }

        public void Mark(string logName, long recordId, DateTime timestampUtc)
        {
            if (!Enabled || String.IsNullOrWhiteSpace(logName) || recordId <= 0) return;

            EnsureLoaded();
            lock (gate)
            {
                EventLogWatermark existing;
                if (watermarks.TryGetValue(logName, out existing) &&
                    !ShouldReplace(existing, recordId, timestampUtc))
                {
                    return;
                }

                EventLogWatermark updated = new EventLogWatermark();
                updated.RecordId = recordId;
                updated.TimestampUtc = timestampUtc.Kind == DateTimeKind.Utc
                    ? timestampUtc
                    : timestampUtc.ToUniversalTime();
                watermarks[logName] = updated;
                SaveLocked();
            }
        }

        private bool Enabled
        {
            get
            {
                return config != null &&
                    config.PersistEventLogWatermarks &&
                    !String.IsNullOrWhiteSpace(config.EventLogWatermarkFile);
            }
        }

        private void EnsureLoaded()
        {
            lock (gate)
            {
                if (loaded) return;
                loaded = true;
                if (!Enabled || !File.Exists(config.EventLogWatermarkFile)) return;

                try
                {
                    foreach (string rawLine in File.ReadAllLines(config.EventLogWatermarkFile))
                    {
                        string line = rawLine.Trim();
                        if (line.Length == 0 || line.StartsWith("#", StringComparison.Ordinal)) continue;

                        string[] parts = line.Split('\t');
                        if (parts.Length < 2) continue;

                        long recordId;
                        if (!Int64.TryParse(parts[1], NumberStyles.Integer, CultureInfo.InvariantCulture, out recordId) || recordId <= 0)
                        {
                            continue;
                        }

                        DateTime timestampUtc = DateTime.MinValue;
                        if (parts.Length >= 3)
                        {
                            DateTime parsed;
                            if (DateTime.TryParse(parts[2], CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out parsed))
                            {
                                timestampUtc = parsed.ToUniversalTime();
                            }
                        }

                        EventLogWatermark watermark = new EventLogWatermark();
                        watermark.RecordId = recordId;
                        watermark.TimestampUtc = timestampUtc;
                        watermarks[parts[0]] = watermark;
                    }
                }
                catch (Exception ex)
                {
                    if (!warnedLoad && logger != null)
                    {
                        logger.Warn("Event log watermark load failed: " + ex.Message);
                        warnedLoad = true;
                    }
                }
            }
        }

        private void SaveLocked()
        {
            try
            {
                string directory = Path.GetDirectoryName(config.EventLogWatermarkFile);
                if (!String.IsNullOrWhiteSpace(directory)) Directory.CreateDirectory(directory);

                List<string> keys = new List<string>(watermarks.Keys);
                keys.Sort(StringComparer.OrdinalIgnoreCase);

                List<string> lines = new List<string>();
                foreach (string key in keys)
                {
                    EventLogWatermark watermark = watermarks[key];
                    string timestamp = watermark.TimestampUtc == DateTime.MinValue
                        ? ""
                        : watermark.TimestampUtc.ToUniversalTime().ToString("o", CultureInfo.InvariantCulture);
                    lines.Add(Sanitize(key) + "\t" + watermark.RecordId.ToString(CultureInfo.InvariantCulture) + "\t" + timestamp);
                }

                string temp = config.EventLogWatermarkFile + ".tmp";
                File.WriteAllLines(temp, lines.ToArray());
                if (File.Exists(config.EventLogWatermarkFile)) File.Delete(config.EventLogWatermarkFile);
                File.Move(temp, config.EventLogWatermarkFile);
            }
            catch (Exception ex)
            {
                if (!warnedSave && logger != null)
                {
                    logger.Warn("Event log watermark save failed: " + ex.Message);
                    warnedSave = true;
                }
            }
        }

        private static bool ShouldReplace(EventLogWatermark existing, long recordId, DateTime timestampUtc)
        {
            if (existing == null || existing.RecordId <= 0) return true;
            if (recordId > existing.RecordId) return true;
            if (timestampUtc == DateTime.MinValue || existing.TimestampUtc == DateTime.MinValue) return false;
            return timestampUtc.ToUniversalTime() > existing.TimestampUtc.ToUniversalTime().AddMinutes(1.0);
        }

        private static string Sanitize(string value)
        {
            return (value ?? "").Replace('\t', ' ').Trim();
        }

        private static EventLogWatermark Empty()
        {
            EventLogWatermark watermark = new EventLogWatermark();
            watermark.RecordId = 0;
            watermark.TimestampUtc = DateTime.MinValue;
            return watermark;
        }

        private static EventLogWatermark Copy(EventLogWatermark source)
        {
            EventLogWatermark copy = new EventLogWatermark();
            copy.RecordId = source.RecordId;
            copy.TimestampUtc = source.TimestampUtc;
            return copy;
        }
    }
}
