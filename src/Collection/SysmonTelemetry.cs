using System.Collections.Generic;

namespace ArcaneEDR
{
    internal sealed class SysmonTelemetry
    {
        public SysmonTelemetry()
        {
            NetworkConnections = new List<NetworkEndpoint>();
            DnsQueries = new List<DnsQueryEvent>();
            ProcessEvents = new List<SysmonProcessEvent>();
        }

        public List<NetworkEndpoint> NetworkConnections { get; private set; }
        public List<DnsQueryEvent> DnsQueries { get; private set; }
        public List<SysmonProcessEvent> ProcessEvents { get; private set; }
    }
}
