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
        private long lastRecordId;
        private bool warnedUnavailable;

        public PowerShellEventCollector(MonitorConfig config, FileLogger logger, IProcessEnricher processEnricher)
        {
            this.config = config;
            this.logger = logger;
            this.processEnricher = processEnricher;
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
                    EventRecord record;
                    while ((record = reader.ReadEvent()) != null)
                    {
                        using (record)
                        {
                            if (record.RecordId.HasValue && record.RecordId.Value <= lastRecordId)
                            {
                                continue;
                            }

                            if (processes == null)
                            {
                                processes = processEnricher == null
                                    ? new Dictionary<int, ProcessInfo>()
                                    : processEnricher.CaptureProcesses();
                            }

                            telemetry.PowerShellEvents.Add(ParseRecord(record, processes));
                            if (record.RecordId.HasValue && record.RecordId.Value > lastRecordId)
                            {
                                lastRecordId = record.RecordId.Value;
                            }

                            count++;
                            if (count >= config.PowerShellMaxEventsPerPoll)
                            {
                                break;
                            }
                        }
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
            ev.User = GetFirst(data, "User", "ConnectedUser", "RunspaceId");
            ev.HostApplication = GetFirst(data, "HostApplication", "HostName", "Application");
            ev.CommandName = GetFirst(data, "CommandName", "Command");
            ev.ScriptBlockText = GetFirst(data, "ScriptBlockText", "Payload", "ContextInfo");
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

        private static string GetFirst(Dictionary<string, string> data, params string[] keys)
        {
            foreach (string key in keys)
            {
                string value = EventRecordDataReader.Get(data, key);
                if (!String.IsNullOrWhiteSpace(value)) return value;
            }

            return "";
        }
    }
}
