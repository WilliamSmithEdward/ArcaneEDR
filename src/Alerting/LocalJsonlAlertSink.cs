using System;
using System.Globalization;
using System.IO;

namespace ArcaneEDR
{
    internal sealed class LocalJsonlAlertSink : IAlertSink
    {
        private readonly MonitorConfig config;
        private readonly FileLogger logger;
        private readonly object gate = new object();

        public LocalJsonlAlertSink(MonitorConfig config, FileLogger logger)
        {
            this.config = config;
            this.logger = logger;
        }

        public bool IsConfigured
        {
            get { return !String.IsNullOrWhiteSpace(config.LocalJsonlAlertSinkFile); }
        }

        public string MissingConfigurationReason
        {
            get { return IsConfigured ? "" : "LocalJsonlAlertSinkFile is empty."; }
        }

        public void Send(Alert alert)
        {
            string path = config.LocalJsonlAlertSinkFile;
            string directory = Path.GetDirectoryName(path);
            if (!String.IsNullOrWhiteSpace(directory))
            {
                Directory.CreateDirectory(directory);
            }

            lock (gate)
            {
                File.AppendAllText(path, alert.ToJson() + Environment.NewLine);
            }

            logger.Info("Wrote local JSONL alert sink record for " + alert.RuleId +
                " score=" + alert.Score.ToString(CultureInfo.InvariantCulture) +
                " path=" + path);
        }
    }
}
