using System;
using System.Collections.Generic;
using System.Diagnostics.Eventing.Reader;
using System.Globalization;
using System.Net;
using System.Xml;

namespace ArcaneEDR
{
    internal sealed class SysmonEventCollector : ISysmonEventCollector
    {
        private readonly MonitorConfig config;
        private readonly FileLogger logger;
        private readonly IProcessEnricher processEnricher;
        private long lastRecordId;
        private bool warnedUnavailable;

        public SysmonEventCollector(MonitorConfig config, FileLogger logger, IProcessEnricher processEnricher)
        {
            this.config = config;
            this.logger = logger;
            this.processEnricher = processEnricher;
        }

        public SysmonTelemetry Capture()
        {
            SysmonTelemetry telemetry = new SysmonTelemetry();
            if (!config.EnableSysmonIngestion)
            {
                return telemetry;
            }

            try
            {
                Dictionary<int, ProcessInfo> processes = processEnricher.CaptureProcesses();
                EventLogQuery eventQuery = new EventLogQuery(config.SysmonEventLogName, PathType.LogName, BuildQuery());

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

                            ParseRecord(record, processes, telemetry);
                            if (record.RecordId.HasValue && record.RecordId.Value > lastRecordId)
                            {
                                lastRecordId = record.RecordId.Value;
                            }

                            count++;
                            if (count >= config.SysmonMaxEventsPerPoll)
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
                    logger.Warn("Sysmon ingestion unavailable or unreadable: " + ex.Message);
                    warnedUnavailable = true;
                }
            }

            return telemetry;
        }

        private string BuildQuery()
        {
            int milliseconds = Math.Max(1, config.SysmonLookbackMinutes) * 60 * 1000;
            return "*[System[(EventID=1 or EventID=3 or EventID=11 or EventID=22) and TimeCreated[timediff(@SystemTime) <= " +
                milliseconds.ToString(CultureInfo.InvariantCulture) + "]]]";
        }

        private void ParseRecord(EventRecord record, Dictionary<int, ProcessInfo> processes, SysmonTelemetry telemetry)
        {
            Dictionary<string, string> data = ReadEventData(record.ToXml());

            if (record.Id == 1)
            {
                telemetry.ProcessEvents.Add(ParseProcessEvent(record, data));
            }
            else if (record.Id == 3)
            {
                NetworkEndpoint endpoint = ParseNetworkEvent(record, data, processes);
                if (endpoint != null) telemetry.NetworkConnections.Add(endpoint);
            }
            else if (record.Id == 11)
            {
                SysmonFileEvent ev = ParseFileEvent(record, data, processes);
                if (ev != null) telemetry.FileEvents.Add(ev);
            }
            else if (record.Id == 22)
            {
                telemetry.DnsQueries.Add(ParseDnsEvent(record, data));
            }
        }

        private static SysmonProcessEvent ParseProcessEvent(EventRecord record, Dictionary<string, string> data)
        {
            SysmonProcessEvent ev = new SysmonProcessEvent();
            ev.RecordId = record.RecordId.HasValue ? record.RecordId.Value : 0;
            ev.TimestampUtc = record.TimeCreated.HasValue ? record.TimeCreated.Value.ToUniversalTime() : DateTime.UtcNow;
            ev.ProcessGuid = Get(data, "ProcessGuid");
            ev.ProcessId = ReadInt(Get(data, "ProcessId"));
            ev.Image = Get(data, "Image");
            ev.ProcessName = FileName(ev.Image);
            ev.CommandLine = Get(data, "CommandLine");
            ev.CurrentDirectory = Get(data, "CurrentDirectory");
            ev.User = Get(data, "User");
            ev.Hashes = Get(data, "Hashes");
            ev.ParentProcessGuid = Get(data, "ParentProcessGuid");
            ev.ParentProcessId = ReadInt(Get(data, "ParentProcessId"));
            ev.ParentImage = Get(data, "ParentImage");
            ev.ParentProcessName = FileName(ev.ParentImage);
            ev.ParentCommandLine = Get(data, "ParentCommandLine");
            return ev;
        }

        private static SysmonFileEvent ParseFileEvent(EventRecord record, Dictionary<string, string> data, Dictionary<int, ProcessInfo> processes)
        {
            string target = Get(data, "TargetFilename");
            if (String.IsNullOrWhiteSpace(target)) return null;

            int processId = ReadInt(Get(data, "ProcessId"));
            SysmonFileEvent ev = new SysmonFileEvent();
            ev.RecordId = record.RecordId.HasValue ? record.RecordId.Value : 0;
            ev.TimestampUtc = record.TimeCreated.HasValue ? record.TimeCreated.Value.ToUniversalTime() : DateTime.UtcNow;
            ev.ProcessGuid = Get(data, "ProcessGuid");
            ev.ProcessId = processId;
            ev.Image = Get(data, "Image");
            ev.ProcessName = FileName(ev.Image);
            ev.TargetFilename = target;
            ev.User = Get(data, "User");

            ProcessInfo processInfo;
            if (processes.TryGetValue(processId, out processInfo))
            {
                ev.Process = processInfo;
                if (!String.IsNullOrWhiteSpace(processInfo.ProcessName)) ev.ProcessName = processInfo.ProcessName;
                if (!String.IsNullOrWhiteSpace(processInfo.ExecutablePath)) ev.Image = processInfo.ExecutablePath;
                if (!String.IsNullOrWhiteSpace(processInfo.User)) ev.User = processInfo.User;
            }

            return ev;
        }

        private static NetworkEndpoint ParseNetworkEvent(EventRecord record, Dictionary<string, string> data, Dictionary<int, ProcessInfo> processes)
        {
            int processId = ReadInt(Get(data, "ProcessId"));
            int destinationPort = ReadInt(Get(data, "DestinationPort"));
            if (destinationPort <= 0) return null;

            NetworkEndpoint endpoint = new NetworkEndpoint();
            endpoint.Protocol = Get(data, "Protocol").ToUpperInvariant();
            if (endpoint.Protocol.Length == 0) endpoint.Protocol = "TCP";
            endpoint.LocalAddress = ParseIp(Get(data, "SourceIp"));
            endpoint.LocalPort = ReadInt(Get(data, "SourcePort"));
            endpoint.RemoteAddress = ParseIp(Get(data, "DestinationIp"));
            endpoint.RemotePort = destinationPort;
            endpoint.RemoteHost = Get(data, "DestinationHostname");
            endpoint.State = "SYSMON";
            endpoint.ProcessId = processId;
            endpoint.ProcessName = FileName(Get(data, "Image"));
            endpoint.Source = "sysmon:" + (record.RecordId.HasValue ? record.RecordId.Value.ToString(CultureInfo.InvariantCulture) : "0");

            ProcessInfo processInfo;
            if (processes.TryGetValue(processId, out processInfo))
            {
                endpoint.Process = processInfo;
                endpoint.ProcessName = processInfo.ProcessName;
            }

            return endpoint;
        }

        private static DnsQueryEvent ParseDnsEvent(EventRecord record, Dictionary<string, string> data)
        {
            DnsQueryEvent ev = new DnsQueryEvent();
            ev.RecordId = record.RecordId.HasValue ? record.RecordId.Value : 0;
            ev.TimestampUtc = record.TimeCreated.HasValue ? record.TimeCreated.Value.ToUniversalTime() : DateTime.UtcNow;
            ev.ProcessGuid = Get(data, "ProcessGuid");
            ev.ProcessId = ReadInt(Get(data, "ProcessId"));
            ev.Image = Get(data, "Image");
            ev.ProcessName = FileName(ev.Image);
            ev.User = Get(data, "User");
            ev.QueryName = Get(data, "QueryName");
            ev.QueryStatus = Get(data, "QueryStatus");
            ev.QueryResults = Get(data, "QueryResults");
            return ev;
        }

        private static Dictionary<string, string> ReadEventData(string xml)
        {
            Dictionary<string, string> data = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            XmlDocument doc = new XmlDocument();
            doc.LoadXml(xml);

            XmlNodeList nodes = doc.GetElementsByTagName("Data");
            foreach (XmlNode node in nodes)
            {
                XmlAttribute name = node.Attributes == null ? null : node.Attributes["Name"];
                if (name == null) continue;
                data[name.Value] = node.InnerText == null ? "" : node.InnerText;
            }

            return data;
        }

        private static string Get(Dictionary<string, string> data, string key)
        {
            string value;
            return data.TryGetValue(key, out value) ? value : "";
        }

        private static int ReadInt(string value)
        {
            int parsed;
            return Int32.TryParse(value, out parsed) ? parsed : 0;
        }

        private static IPAddress ParseIp(string value)
        {
            IPAddress address;
            return IPAddress.TryParse(value, out address) ? address : IPAddress.None;
        }

        private static string FileName(string path)
        {
            if (String.IsNullOrWhiteSpace(path)) return "";
            int slash = Math.Max(path.LastIndexOf('\\'), path.LastIndexOf('/'));
            return slash >= 0 && slash + 1 < path.Length ? path.Substring(slash + 1) : path;
        }
    }
}
