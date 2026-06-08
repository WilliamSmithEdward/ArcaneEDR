using System.Collections.Generic;

namespace ArcaneEDR
{
    internal sealed class NetworkSnapshot
    {
        public NetworkSnapshot(List<NetworkEndpoint> endpoints)
        {
            Endpoints = OrEmpty(endpoints);
            DnsQueries = new List<DnsQueryEvent>();
            ProcessEvents = new List<SysmonProcessEvent>();
            FileEvents = new List<SysmonFileEvent>();
            HostTelemetry = new HostTelemetry();
        }

        public NetworkSnapshot(List<NetworkEndpoint> endpoints, List<DnsQueryEvent> dnsQueries, List<SysmonProcessEvent> processEvents)
        {
            Endpoints = OrEmpty(endpoints);
            DnsQueries = OrEmpty(dnsQueries);
            ProcessEvents = OrEmpty(processEvents);
            FileEvents = new List<SysmonFileEvent>();
            HostTelemetry = new HostTelemetry();
        }

        public NetworkSnapshot(List<NetworkEndpoint> endpoints, List<DnsQueryEvent> dnsQueries, List<SysmonProcessEvent> processEvents, HostTelemetry hostTelemetry)
        {
            Endpoints = OrEmpty(endpoints);
            DnsQueries = OrEmpty(dnsQueries);
            ProcessEvents = OrEmpty(processEvents);
            FileEvents = new List<SysmonFileEvent>();
            HostTelemetry = hostTelemetry ?? new HostTelemetry();
        }

        public NetworkSnapshot(List<NetworkEndpoint> endpoints, List<DnsQueryEvent> dnsQueries, List<SysmonProcessEvent> processEvents, List<SysmonFileEvent> fileEvents, HostTelemetry hostTelemetry)
        {
            Endpoints = OrEmpty(endpoints);
            DnsQueries = OrEmpty(dnsQueries);
            ProcessEvents = OrEmpty(processEvents);
            FileEvents = OrEmpty(fileEvents);
            HostTelemetry = hostTelemetry ?? new HostTelemetry();
        }

        public List<NetworkEndpoint> Endpoints { get; private set; }
        public List<DnsQueryEvent> DnsQueries { get; private set; }
        public List<SysmonProcessEvent> ProcessEvents { get; private set; }
        public List<SysmonFileEvent> FileEvents { get; private set; }
        public HostTelemetry HostTelemetry { get; private set; }

        private static List<T> OrEmpty<T>(List<T> values)
        {
            return values ?? new List<T>();
        }
    }
}
