using System;
using System.Collections.Generic;
using System.Diagnostics.Eventing.Reader;
using System.Globalization;

namespace ArcaneEDR
{
    internal sealed class WindowsEventCollector : IHostTelemetryCollector
    {
        private readonly MonitorConfig config;
        private readonly FileLogger logger;
        private readonly EventLogWatermarkStore watermarks;
        private readonly Dictionary<string, long> lastRecordIds = new Dictionary<string, long>(StringComparer.OrdinalIgnoreCase);
        private readonly Dictionary<string, DateTime> lastRecordTimestampUtc = new Dictionary<string, DateTime>(StringComparer.OrdinalIgnoreCase);
        private readonly HashSet<string> warnedLogs = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        public WindowsEventCollector(MonitorConfig config, FileLogger logger, EventLogWatermarkStore watermarks)
        {
            this.config = config;
            this.logger = logger;
            this.watermarks = watermarks;
        }

        public HostTelemetry Capture()
        {
            HostTelemetry telemetry = new HostTelemetry();
            if (!config.EnableWindowsEventIngestion)
            {
                return telemetry;
            }

            CaptureLog(config.WindowsSecurityEventLogName, BuildSecurityQuery(), telemetry);
            CaptureLog(config.WindowsSystemEventLogName, BuildSystemQuery(), telemetry);
            return telemetry;
        }

        private void CaptureLog(string logName, string query, HostTelemetry telemetry)
        {
            try
            {
                EventLogQuery eventQuery = new EventLogQuery(logName, PathType.LogName, query);
                using (EventLogReader reader = new EventLogReader(eventQuery))
                {
                    int count = 0;
                    bool advanced = false;
                    EventRecord record;
                    while ((record = reader.ReadEvent()) != null)
                    {
                        using (record)
                        {
                            long last = GetLastRecordId(logName);
                            long recordId = record.RecordId.HasValue ? record.RecordId.Value : 0;
                            DateTime recordTimestampUtc = record.TimeCreated.HasValue ? record.TimeCreated.Value.ToUniversalTime() : DateTime.MinValue;
                            if (recordId > 0 && recordId <= last)
                            {
                                if (IsLikelyLogReset(logName, recordId, recordTimestampUtc))
                                {
                                    lastRecordIds[logName] = 0;
                                    lastRecordTimestampUtc[logName] = DateTime.MinValue;
                                    last = 0;
                                }
                                else
                                {
                                    continue;
                                }
                            }

                            telemetry.WindowsEvents.Add(ParseRecord(logName, record));
                            if (recordId > last)
                            {
                                lastRecordIds[logName] = recordId;
                                lastRecordTimestampUtc[logName] = recordTimestampUtc == DateTime.MinValue ? DateTime.UtcNow : recordTimestampUtc;
                                advanced = true;
                            }

                            count++;
                            if (count >= config.WindowsEventMaxEventsPerPoll)
                            {
                                break;
                            }
                        }
                    }

                    if (advanced && watermarks != null)
                    {
                        watermarks.Mark(logName, GetLastRecordId(logName), GetLastRecordTimestampUtc(logName));
                    }
                }
            }
            catch (Exception ex)
            {
                if (!warnedLogs.Contains(logName))
                {
                    logger.Warn(logName + " event ingestion unavailable or unreadable: " + ex.Message);
                    warnedLogs.Add(logName);
                }
            }
        }

        private string BuildSecurityQuery()
        {
            int milliseconds = Math.Max(1, config.WindowsEventLookbackMinutes) * 60 * 1000;
            return "*[System[(EventID=4624 or EventID=4625 or EventID=4672 or EventID=4688 or EventID=4697 or EventID=4698 or EventID=4702) and TimeCreated[timediff(@SystemTime) <= " +
                milliseconds.ToString(CultureInfo.InvariantCulture) + "]]]";
        }

        private string BuildSystemQuery()
        {
            int milliseconds = Math.Max(1, config.WindowsEventLookbackMinutes) * 60 * 1000;
            return "*[System[(EventID=7045) and TimeCreated[timediff(@SystemTime) <= " +
                milliseconds.ToString(CultureInfo.InvariantCulture) + "]]]";
        }

        private long GetLastRecordId(string logName)
        {
            EnsureWatermarkLoaded(logName);
            long value;
            return lastRecordIds.TryGetValue(logName, out value) ? value : 0;
        }

        private DateTime GetLastRecordTimestampUtc(string logName)
        {
            EnsureWatermarkLoaded(logName);
            DateTime value;
            return lastRecordTimestampUtc.TryGetValue(logName, out value) ? value : DateTime.MinValue;
        }

        private void EnsureWatermarkLoaded(string logName)
        {
            if (lastRecordIds.ContainsKey(logName)) return;

            EventLogWatermark watermark = watermarks == null ? null : watermarks.Get(logName);
            lastRecordIds[logName] = watermark == null ? 0 : watermark.RecordId;
            lastRecordTimestampUtc[logName] = watermark == null ? DateTime.MinValue : watermark.TimestampUtc;
        }

        private bool IsLikelyLogReset(string logName, long recordId, DateTime recordTimestampUtc)
        {
            long last = GetLastRecordId(logName);
            DateTime lastTimestampUtc = GetLastRecordTimestampUtc(logName);
            return last > 0 &&
                recordId > 0 &&
                recordId <= last &&
                lastTimestampUtc != DateTime.MinValue &&
                recordTimestampUtc != DateTime.MinValue &&
                recordTimestampUtc > lastTimestampUtc.AddMinutes(1.0);
        }

        private static WindowsAuditEvent ParseRecord(string logName, EventRecord record)
        {
            Dictionary<string, string> data = EventRecordDataReader.ReadEventData(record);
            WindowsAuditEvent ev = new WindowsAuditEvent();
            ev.RecordId = record.RecordId.HasValue ? record.RecordId.Value : 0;
            ev.LogName = logName;
            ev.EventId = record.Id;
            ev.TimestampUtc = record.TimeCreated.HasValue ? record.TimeCreated.Value.ToUniversalTime() : DateTime.UtcNow;
            ev.SubjectUser = CombineDomainUser(GetFirst(data, "SubjectDomainName"), GetFirst(data, "SubjectUserName"));
            ev.TargetUser = CombineDomainUser(GetFirst(data, "TargetDomainName"), GetFirst(data, "TargetUserName", "AccountName"));
            ev.IpAddress = GetFirst(data, "IpAddress", "ClientAddress", "WorkstationName");
            ev.LogonType = GetFirst(data, "LogonType");
            ev.ProcessName = GetFirst(data, "ProcessName", "NewProcessName", "Application");
            ev.ParentProcessName = GetFirst(data, "ParentProcessName", "CreatorProcessName", "ParentImage");
            ev.ServiceName = GetFirst(data, "ServiceName", "ServiceFileName");
            ev.TaskName = GetFirst(data, "TaskName");
            ev.CommandLine = GetFirst(data, "CommandLine", "ProcessCommandLine", "ServiceFileName", "ImagePath", "TaskContentNew", "TaskContent", "ActionName");
            ev.Message = EventRecordDataReader.FormatDescription(record);
            return ev;
        }

        private static string GetFirst(Dictionary<string, string> data, params string[] keys)
        {
            foreach (string key in keys)
            {
                string value = EventRecordDataReader.Get(data, key);
                if (!String.IsNullOrWhiteSpace(value)) return value;
            }

            return "";
        }

        private static string CombineDomainUser(string domain, string user)
        {
            if (String.IsNullOrWhiteSpace(user)) return "";
            if (String.IsNullOrWhiteSpace(domain) || domain.Equals("-", StringComparison.Ordinal)) return user;
            return domain + "\\" + user;
        }
    }
}
