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
            HostIdentitySnapshot host = alert.HostIdentity;
            string message =
                "Rule: " + alert.RuleId + Environment.NewLine +
                "Category: " + AlertRulePolicy.AlertCategory(alert) + Environment.NewLine +
                "LocalMachine: " + host.DisplayName + Environment.NewLine +
                "LocalDnsHostname: " + host.DnsHostName + Environment.NewLine +
                "LocalIpAddresses: " + host.LocalIpAddressSummary + Environment.NewLine +
                "MaintenanceContext: " + alert.MaintenanceContext + Environment.NewLine +
                "Severity: " + alert.Severity + Environment.NewLine +
                "Score: " + alert.Score.ToString(CultureInfo.InvariantCulture) + Environment.NewLine +
                "UTC: " + UtcTimestamp.Format(alert.TimestampUtc) + Environment.NewLine +
                "SystemLocalTime: " + alert.SystemLocalTime + Environment.NewLine +
                "Title: " + alert.Title + Environment.NewLine +
                "Why: " + TextFormatting.CompactOrEmpty(AlertWhyText.Join(alert, "; "), 2000) + Environment.NewLine +
                "Details: " + TextFormatting.CompactOrEmpty(alert.Body, 3000) + Environment.NewLine +
                "Recommendation: " + TextFormatting.CompactOrEmpty(alert.Recommendation, 1000) + Environment.NewLine +
                "Entity: " + TextFormatting.CompactOrEmpty(alert.EntitySummary, 2000);

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

    }
}
