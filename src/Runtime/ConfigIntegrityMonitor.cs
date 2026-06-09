using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;

namespace ArcaneEDR
{
    internal sealed class ConfigIntegrityMonitor
    {
        private readonly MonitorConfig config;
        private readonly FileLogger logger;
        private readonly Dictionary<string, string> knownHashes = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        public ConfigIntegrityMonitor(MonitorConfig config, FileLogger logger)
        {
            this.config = config;
            this.logger = logger;
            Remember(config.ConfigPath);
            Remember(config.RemoteEndpointPolicyFile);
            Remember(typeof(ConfigIntegrityMonitor).Assembly.Location);
        }

        public List<Alert> Check()
        {
            List<Alert> alerts = new List<Alert>();
            CheckPath(config.ConfigPath, "APP-CONFIG-CHANGED", "Monitor configuration changed", alerts);
            CheckPath(config.RemoteEndpointPolicyFile, "APP-REMOTE-ENDPOINT-POLICY-CHANGED", "Remote endpoint policy changed", alerts);
            CheckPath(typeof(ConfigIntegrityMonitor).Assembly.Location, "APP-BINARY-CHANGED", "Monitor executable changed", alerts);
            return alerts;
        }

        private void CheckPath(string path, string ruleId, string title, List<Alert> alerts)
        {
            if (String.IsNullOrWhiteSpace(path) || !File.Exists(path)) return;

            string current = Hash(path);
            string previous;
            if (!knownHashes.TryGetValue(path, out previous))
            {
                knownHashes[path] = current;
                return;
            }

            if (!String.Equals(previous, current, StringComparison.OrdinalIgnoreCase))
            {
                knownHashes[path] = current;
                alerts.Add(Alert.Create(
                    ruleId,
                    title,
                    75,
                    "Integrity hash changed for " + path + ".",
                    "Confirm this change was intentional. If not, preserve the file and logs for investigation.",
                    "integrity|" + path));
            }
        }

        private void Remember(string path)
        {
            try
            {
                if (!String.IsNullOrWhiteSpace(path) && File.Exists(path))
                {
                    knownHashes[path] = Hash(path);
                }
            }
            catch (Exception ex)
            {
                logger.Warn("Integrity baseline failed for " + path + ": " + ex.Message);
            }
        }

        private static string Hash(string path)
        {
            using (FileStream stream = File.Open(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete))
            using (SHA256 sha = SHA256.Create())
            {
                return BitConverter.ToString(sha.ComputeHash(stream)).Replace("-", "").ToLowerInvariant();
            }
        }
    }
}
