using System;
using System.Globalization;
using System.IO;

namespace ArcaneEDR
{
    internal sealed class FileLogger
    {
        private readonly string logDirectory;
        private readonly long maxLogFileBytes;
        private readonly object gate = new object();

        public FileLogger(string logDirectory, long maxLogFileBytes)
        {
            this.logDirectory = logDirectory;
            this.maxLogFileBytes = maxLogFileBytes <= 0 ? 10485760 : maxLogFileBytes;
            Directory.CreateDirectory(logDirectory);
        }

        public void Info(string message)
        {
            Write("INFO", message);
        }

        public void Warn(string message)
        {
            Write("WARN", message);
        }

        public void Error(string message)
        {
            Write("ERROR", message);
        }

        public void Alert(Alert alert)
        {
            string body = alert.Body ?? "";
            Write("ALERT", "[" + alert.Score.ToString(CultureInfo.InvariantCulture) + "] " +
                alert.RuleId + " category=" + AlertRulePolicy.AlertCategory(alert) + " " +
                "maintenance_context=" + alert.MaintenanceContext + " " +
                "system_local_time=\"" + alert.SystemLocalTime + "\" " +
                alert.Title + " | " + AlertWhyText.JoinWithPrefix(alert, "Why: ", "; ", " | ") + body.Replace(Environment.NewLine, " | "));
            try
            {
                AppendLine("ArcaneAlerts.jsonl", alert.ToJson());
            }
            catch (Exception ex)
            {
                Write("WARN", "Alert JSONL write failed: " + ex.Message);
            }
        }

        private void Write(string level, string message)
        {
            string line = DateTime.UtcNow.ToString("u", CultureInfo.InvariantCulture) + " " + level + " " + message;
            Console.WriteLine(line);
            try
            {
                AppendLine("ArcaneEDR.log", line);
            }
            catch
            {
            }
        }

        private void AppendLine(string fileName, string line)
        {
            lock (gate)
            {
                string path = Path.Combine(logDirectory, fileName);
                LogFileRotation.RotateIfNeeded(path, maxLogFileBytes);
                File.AppendAllText(path, line + Environment.NewLine);
            }
        }
    }
}
