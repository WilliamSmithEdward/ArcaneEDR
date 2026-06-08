using System;
using System.Globalization;
using System.IO;

namespace ArcaneEDR
{
    internal sealed class DailyReportArchive
    {
        private readonly MonitorConfig config;
        private readonly FileLogger logger;

        public DailyReportArchive(MonitorConfig config, FileLogger logger)
        {
            this.config = config;
            this.logger = logger;
        }

        public void Save(DailyReportSnapshot snapshot, string markdownReport, string jsonReport)
        {
            if (config == null || !config.EnableDailyReportArchive) return;

            try
            {
                Directory.CreateDirectory(config.DailyReportArchiveDirectory);
                string stamp = snapshot.GeneratedUtc.ToUniversalTime().ToString("yyyyMMddTHHmmssfffZ", CultureInfo.InvariantCulture);
                string basePath = ResolveArchiveBasePath(stamp);
                int written = 0;

                if (FormatEnabled("Markdown"))
                {
                    File.WriteAllText(basePath + ".md", markdownReport ?? "");
                    written++;
                }

                if (FormatEnabled("Json"))
                {
                    File.WriteAllText(basePath + ".json", jsonReport ?? "");
                    written++;
                }

                if (written > 0 && logger != null)
                {
                    logger.Info("Daily report archived files=" + written.ToString(CultureInfo.InvariantCulture) +
                        " directory=" + config.DailyReportArchiveDirectory);
                }
            }
            catch (Exception ex)
            {
                if (logger != null)
                {
                    logger.Warn("Daily report archive failed: " + ex.Message);
                }
            }
        }

        private bool FormatEnabled(string format)
        {
            return config.DailyReportArchiveFormats != null &&
                config.DailyReportArchiveFormats.Contains(format);
        }

        private string ResolveArchiveBasePath(string stamp)
        {
            string candidate = Path.Combine(config.DailyReportArchiveDirectory, "daily-report-" + stamp);
            int suffix = 1;
            while (ArchiveExists(candidate))
            {
                candidate = Path.Combine(
                    config.DailyReportArchiveDirectory,
                    "daily-report-" + stamp + "-" + suffix.ToString(CultureInfo.InvariantCulture));
                suffix++;
            }

            return candidate;
        }

        private bool ArchiveExists(string basePath)
        {
            return File.Exists(basePath + ".md") || File.Exists(basePath + ".json");
        }
    }
}
