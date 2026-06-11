using System;
using System.Collections.Generic;
using System.Diagnostics.Eventing.Reader;
using System.Globalization;

namespace ArcaneEDR
{
    internal sealed class PowerShellEventCollector : IHostTelemetryCollector
    {
        private readonly MonitorConfig config;
        private readonly FileLogger logger;
        private readonly IProcessEnricher processEnricher;
        private readonly EventLogWatermarkStore watermarks;
        private long lastRecordId;
        private DateTime lastRecordTimestampUtc = DateTime.MinValue;
        private bool warnedUnavailable;

        public PowerShellEventCollector(MonitorConfig config, FileLogger logger, IProcessEnricher processEnricher, EventLogWatermarkStore watermarks)
        {
            this.config = config;
            this.logger = logger;
            this.processEnricher = processEnricher;
            this.watermarks = watermarks;

            EventLogWatermark watermark = watermarks == null ? null : watermarks.Get(config.PowerShellEventLogName);
            if (watermark != null)
            {
                lastRecordId = watermark.RecordId;
                lastRecordTimestampUtc = watermark.TimestampUtc;
            }
        }

        public HostTelemetry Capture()
        {
            HostTelemetry telemetry = new HostTelemetry();
            if (!config.EnablePowerShellLogIngestion)
            {
                return telemetry;
            }

            try
            {
                Dictionary<int, ProcessInfo> processes = null;
                EventLogQuery eventQuery = new EventLogQuery(config.PowerShellEventLogName, PathType.LogName, BuildQuery());
                using (EventLogReader reader = new EventLogReader(eventQuery))
                {
                    int count = 0;
                    bool advanced = false;
                    EventRecord record;
                    while ((record = reader.ReadEvent()) != null)
                    {
                        using (record)
                        {
                            long recordId = record.RecordId.HasValue ? record.RecordId.Value : 0;
                            DateTime recordTimestampUtc = record.TimeCreated.HasValue ? record.TimeCreated.Value.ToUniversalTime() : DateTime.MinValue;
                            if (recordId > 0 && recordId <= lastRecordId)
                            {
                                if (EventLogRecordState.IsLikelyReset(recordId, recordTimestampUtc, lastRecordId, lastRecordTimestampUtc))
                                {
                                    lastRecordId = 0;
                                    lastRecordTimestampUtc = DateTime.MinValue;
                                }
                                else
                                {
                                    continue;
                                }
                            }

                            if (processes == null)
                            {
                                processes = processEnricher == null
                                    ? new Dictionary<int, ProcessInfo>()
                                    : processEnricher.CaptureProcesses();
                            }

                            telemetry.PowerShellEvents.Add(ParseRecord(record, processes));
                            if (recordId > lastRecordId)
                            {
                                lastRecordId = recordId;
                                lastRecordTimestampUtc = recordTimestampUtc == DateTime.MinValue ? DateTime.UtcNow : recordTimestampUtc;
                                advanced = true;
                            }

                            count++;
                            if (count >= config.PowerShellMaxEventsPerPoll)
                            {
                                break;
                            }
                        }
                    }

                    if (advanced && watermarks != null)
                    {
                        watermarks.Mark(config.PowerShellEventLogName, lastRecordId, lastRecordTimestampUtc);
                    }
                }
            }
            catch (Exception ex)
            {
                if (!warnedUnavailable)
                {
                    logger.Warn("PowerShell event ingestion unavailable or unreadable: " + ex.Message);
                    warnedUnavailable = true;
                }
            }

            return telemetry;
        }

        private string BuildQuery()
        {
            int milliseconds = Math.Max(1, config.PowerShellLookbackMinutes) * 60 * 1000;
            return "*[System[(EventID=400 or EventID=403 or EventID=4103 or EventID=4104) and TimeCreated[timediff(@SystemTime) <= " +
                milliseconds.ToString(CultureInfo.InvariantCulture) + "]]]";
        }

        private static PowerShellEvent ParseRecord(EventRecord record, Dictionary<int, ProcessInfo> processes)
        {
            Dictionary<string, string> data = EventRecordDataReader.ReadEventData(record);
            PowerShellEvent ev = new PowerShellEvent();
            ev.RecordId = record.RecordId.HasValue ? record.RecordId.Value : 0;
            ev.EventId = record.Id;
            ev.ProcessId = record.ProcessId.HasValue ? record.ProcessId.Value : 0;
            ev.ThreadId = record.ThreadId.HasValue ? record.ThreadId.Value : 0;
            ev.TimestampUtc = record.TimeCreated.HasValue ? record.TimeCreated.Value.ToUniversalTime() : DateTime.UtcNow;
            ev.User = EventRecordDataReader.GetFirst(data, "User", "ConnectedUser", "RunspaceId");
            ev.HostApplication = EventRecordDataReader.GetFirst(data, "HostApplication", "HostName", "Application");
            ev.CommandName = EventRecordDataReader.GetFirst(data, "CommandName", "Command");
            ev.ScriptBlockText = EventRecordDataReader.GetFirst(data, "ScriptBlockText", "Payload", "ContextInfo");
            ev.Message = EventRecordDataReader.FormatDescription(record);
            EnrichProcessContext(ev, processes);
            return ev;
        }

        private static void EnrichProcessContext(PowerShellEvent ev, Dictionary<int, ProcessInfo> processes)
        {
            if (ev == null || processes == null || ev.ProcessId <= 0) return;

            ProcessInfo process;
            if (!processes.TryGetValue(ev.ProcessId, out process)) return;

            ev.ProcessName = process.ProcessName;
            ev.ProcessPath = process.ExecutablePath;
            ev.ProcessCommandLine = process.CommandLine;
            ev.ParentProcessId = process.ParentProcessId;
            ev.ParentProcessName = process.ParentProcessName;
            ev.ParentProcessPath = process.ParentExecutablePath;
            ev.ParentCommandLine = process.ParentCommandLine;
            ev.ProcessUser = process.User;
            ev.ProcessSha256 = process.Sha256;
            ev.ProcessSigner = process.Signer;
        }

    }
}
