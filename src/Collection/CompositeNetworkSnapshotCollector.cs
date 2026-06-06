using System.Collections.Generic;

namespace ArcaneEDR
{
    internal sealed class CompositeNetworkSnapshotCollector : INetworkSnapshotCollector
    {
        private readonly INetworkSnapshotCollector networkCollector;
        private readonly ISysmonEventCollector sysmonCollector;
        private readonly IHostTelemetryCollector hostTelemetryCollector;

        public CompositeNetworkSnapshotCollector(INetworkSnapshotCollector networkCollector, ISysmonEventCollector sysmonCollector, IHostTelemetryCollector hostTelemetryCollector)
        {
            this.networkCollector = networkCollector;
            this.sysmonCollector = sysmonCollector;
            this.hostTelemetryCollector = hostTelemetryCollector;
        }

        public NetworkSnapshot Capture()
        {
            NetworkSnapshot networkSnapshot = networkCollector.Capture();
            SysmonTelemetry sysmon = sysmonCollector.Capture();
            HostTelemetry hostTelemetry = hostTelemetryCollector.Capture();

            List<NetworkEndpoint> endpoints = new List<NetworkEndpoint>(networkSnapshot.Endpoints);
            endpoints.AddRange(sysmon.NetworkConnections);

            return new NetworkSnapshot(endpoints, sysmon.DnsQueries, sysmon.ProcessEvents, hostTelemetry);
        }
    }
}
