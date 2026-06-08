using System;
using System.Diagnostics;
using System.Globalization;

namespace ArcaneEDR
{
    internal sealed class WindowsEventLogAlertSink : IAlertSink
    {
        private readonly MonitorConfig config;
        private readonly FileLogger logger;

        public WindowsEventLogAlertSink(MonitorConfig config, FileLogger logger)
        {
            this.config = config;
            this.logger = logger;
        }

        public bool IsConfigured
        {
            get
            {
                return !String.IsNullOrWhiteSpace(config.WindowsEventLogAlertSource) &&
                    !String.IsNullOrWhiteSpace(config.WindowsEventLogAlertLogName);
            }
        }

        public string MissingConfigurationReason
        {
            get
            {
                return IsConfigured
                    ? ""
                    : "WindowsEventLogAlertSource or WindowsEventLogAlertLogName is empty.";
            }
        }

        public bool Send(Alert alert)
        {
            EnsureSource();
            EventLogEntryType entryType = EntryTypeFor(alert);
            string message =
                "Rule: " + alert.RuleId + Environment.NewLine +
                "Category: " + AlertRulePolicy.AlertCategory(alert) + Environment.NewLine +
                "MaintenanceContext: " + alert.MaintenanceContext + Environment.NewLine +
                "Severity: " + alert.Severity + Environment.NewLine +
                "Score: " + alert.Score.ToString(CultureInfo.InvariantCulture) + Environment.NewLine +
                "UTC: " + alert.TimestampUtc.ToString("yyyy-MM-ddTHH:mm:ssZ", CultureInfo.InvariantCulture) + Environment.NewLine +
                "SystemLocalTime: " + alert.SystemLocalTime + Environment.NewLine +
                "Title: " + alert.Title + Environment.NewLine +
                "Why: " + Compact(WhyText(alert), 2000) + Environment.NewLine +
                "Details: " + Compact(alert.Body, 3000) + Environment.NewLine +
                "Recommendation: " + Compact(alert.Recommendation, 1000) + Environment.NewLine +
                "Entity: " + Compact(alert.EntitySummary, 2000);

            EventLog.WriteEntry(config.WindowsEventLogAlertSource, message, entryType, config.WindowsEventLogAlertEventId);
            logger.Info("Wrote Windows Event Log alert for " + alert.RuleId +
                " source=" + config.WindowsEventLogAlertSource +
                " event_id=" + config.WindowsEventLogAlertEventId.ToString(CultureInfo.InvariantCulture));
            return true;
        }

        private void EnsureSource()
        {
            if (EventLog.SourceExists(config.WindowsEventLogAlertSource)) return;

            EventSourceCreationData data = new EventSourceCreationData(
                config.WindowsEventLogAlertSource,
                config.WindowsEventLogAlertLogName);
            EventLog.CreateEventSource(data);
        }

        private static EventLogEntryType EntryTypeFor(Alert alert)
        {
            if (alert.Score >= 75) return EventLogEntryType.Error;
            if (alert.Score >= 50) return EventLogEntryType.Warning;
            return EventLogEntryType.Information;
        }

        private static string WhyText(Alert alert)
        {
            if (alert.Why == null || alert.Why.Count == 0) return "";
            return String.Join("; ", alert.Why.ToArray());
        }

        private static string Compact(string value, int maxLength)
        {
            if (String.IsNullOrWhiteSpace(value)) return "";
            string compact = value.Replace("\r", " ").Replace("\n", " ").Trim();
            if (compact.Length <= maxLength) return compact;
            return compact.Substring(0, maxLength) + "...";
        }
    }
}
