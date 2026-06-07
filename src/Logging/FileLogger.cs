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
            Write("ALERT", "[" + alert.Score.ToString(CultureInfo.InvariantCulture) + "] " +
                alert.RuleId + " category=" + AlertRulePolicy.AlertCategory(alert) + " " +
                alert.Title + " | " + WhyText(alert) + alert.Body.Replace(Environment.NewLine, " | "));
            try
            {
                AppendLine("ArcaneAlerts.jsonl", alert.ToJson());
            }
            catch (Exception ex)
            {
                Write("WARN", "Alert JSONL write failed: " + ex.Message);
            }
        }

        private static string WhyText(Alert alert)
        {
            if (alert.Why == null || alert.Why.Count == 0) return "";
            return "Why: " + String.Join("; ", alert.Why.ToArray()) + " | ";
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
                RotateIfNeeded(path);
                File.AppendAllText(path, line + Environment.NewLine);
            }
        }

        private void RotateIfNeeded(string path)
        {
            try
            {
                FileInfo file = new FileInfo(path);
                if (!file.Exists || file.Length < maxLogFileBytes) return;

                string rotated = path + "." + DateTime.UtcNow.ToString("yyyyMMddHHmmss", CultureInfo.InvariantCulture) + ".old";
                File.Move(path, rotated);
            }
            catch
            {
            }
        }
    }
}
