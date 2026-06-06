using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;

namespace ArcaneEDR
{
    internal sealed class ReputationCache
    {
        private readonly MonitorConfig config;
        private readonly FileLogger logger;
        private readonly HashSet<string> seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        private readonly object gate = new object();
        private bool loaded;

        public ReputationCache(MonitorConfig config, FileLogger logger)
        {
            this.config = config;
            this.logger = logger;
        }

        public bool Observe(string kind, string key, string detail)
        {
            if (!config.EnableReputationCache || String.IsNullOrWhiteSpace(key))
            {
                return false;
            }

            EnsureLoaded();
            string identity = kind + "|" + key;

            lock (gate)
            {
                if (seen.Contains(identity))
                {
                    return false;
                }

                seen.Add(identity);
                Append(kind, key, detail);
                return true;
            }
        }

        private void EnsureLoaded()
        {
            if (loaded) return;

            lock (gate)
            {
                if (loaded) return;
                try
                {
                    if (File.Exists(config.ReputationCacheFile))
                    {
                        foreach (string line in File.ReadAllLines(config.ReputationCacheFile))
                        {
                            string[] parts = line.Split('\t');
                            if (parts.Length >= 2)
                            {
                                seen.Add(parts[0] + "|" + parts[1]);
                            }
                        }
                    }
                }
                catch (Exception ex)
                {
                    logger.Warn("Reputation cache load failed: " + ex.Message);
                }

                loaded = true;
            }
        }

        private void Append(string kind, string key, string detail)
        {
            try
            {
                string directory = Path.GetDirectoryName(config.ReputationCacheFile);
                if (!String.IsNullOrWhiteSpace(directory))
                {
                    Directory.CreateDirectory(directory);
                }

                string line = kind + "\t" + key + "\t" +
                    DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ", CultureInfo.InvariantCulture) + "\t" +
                    Clean(detail);
                File.AppendAllText(config.ReputationCacheFile, line + Environment.NewLine);
            }
            catch (Exception ex)
            {
                logger.Warn("Reputation cache append failed: " + ex.Message);
            }
        }

        private static string Clean(string value)
        {
            if (value == null) return "";
            return value.Replace("\t", " ").Replace("\r", " ").Replace("\n", " ");
        }
    }
}
