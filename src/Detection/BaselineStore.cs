using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;

namespace ArcaneEDR
{
    internal sealed class BaselineStore
    {
        private const string CreatedPrefix = "#created_utc=";
        private readonly MonitorConfig config;
        private readonly FileLogger logger;
        private readonly object gate = new object();
        private readonly HashSet<string> keys = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        private DateTime createdUtc;

        public BaselineStore(MonitorConfig config, FileLogger logger)
        {
            this.config = config;
            this.logger = logger;
            createdUtc = DateTime.UtcNow;
            Load();
        }

        public bool IsWarmupActive
        {
            get
            {
                if (!config.BaselineEnabled) return false;
                return (DateTime.UtcNow - createdUtc).TotalHours < config.BaselineWarmupHours;
            }
        }

        public bool Observe(string category, string value)
        {
            if (!config.BaselineEnabled || String.IsNullOrWhiteSpace(value)) return false;

            string key = category + "\t" + value.Trim();
            lock (gate)
            {
                if (keys.Contains(key)) return false;
                keys.Add(key);
                Persist(key);
                return true;
            }
        }

        private void Load()
        {
            try
            {
                Directory.CreateDirectory(Path.GetDirectoryName(config.BaselineFile));
                if (!File.Exists(config.BaselineFile))
                {
                    File.AppendAllText(config.BaselineFile, CreatedPrefix + UtcTimestamp.Format(createdUtc) + Environment.NewLine);
                    return;
                }

                foreach (string line in File.ReadAllLines(config.BaselineFile))
                {
                    if (line.StartsWith(CreatedPrefix, StringComparison.OrdinalIgnoreCase))
                    {
                        DateTime parsed;
                        if (DateTime.TryParse(line.Substring(CreatedPrefix.Length), out parsed))
                        {
                            createdUtc = parsed.ToUniversalTime();
                        }
                        continue;
                    }

                    if (line.Trim().Length > 0)
                    {
                        keys.Add(line.Trim());
                    }
                }
            }
            catch (Exception ex)
            {
                logger.Warn("Baseline load failed: " + ex.Message);
            }
        }

        private void Persist(string key)
        {
            try
            {
                File.AppendAllText(config.BaselineFile, key + Environment.NewLine);
            }
            catch (Exception ex)
            {
                logger.Warn("Baseline persist failed: " + ex.Message);
            }
        }
    }
}
