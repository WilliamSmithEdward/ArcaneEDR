using System.Collections.Generic;

namespace ArcaneEDR
{
    internal sealed class NetworkSnapshot
    {
        public NetworkSnapshot(List<NetworkEndpoint> endpoints)
        {
            Endpoints = endpoints;
            DnsQueries = new List<DnsQueryEvent>();
            ProcessEvents = new List<SysmonProcessEvent>();
            HostTelemetry = new HostTelemetry();
        }

        public NetworkSnapshot(List<NetworkEndpoint> endpoints, List<DnsQueryEvent> dnsQueries, List<SysmonProcessEvent> processEvents)
        {
            Endpoints = endpoints;
            DnsQueries = dnsQueries;
            ProcessEvents = processEvents;
            HostTelemetry = new HostTelemetry();
        }

        public NetworkSnapshot(List<NetworkEndpoint> endpoints, List<DnsQueryEvent> dnsQueries, List<SysmonProcessEvent> processEvents, HostTelemetry hostTelemetry)
        {
            Endpoints = endpoints;
            DnsQueries = dnsQueries;
            ProcessEvents = processEvents;
            HostTelemetry = hostTelemetry ?? new HostTelemetry();
        }

        public List<NetworkEndpoint> Endpoints { get; private set; }
        public List<DnsQueryEvent> DnsQueries { get; private set; }
        public List<SysmonProcessEvent> ProcessEvents { get; private set; }
        public HostTelemetry HostTelemetry { get; private set; }
    }
}
