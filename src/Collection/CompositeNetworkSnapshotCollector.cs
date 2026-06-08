using System;
using System.Collections.Generic;

namespace ArcaneEDR
{
    internal sealed class CompositeNetworkSnapshotCollector : INetworkSnapshotCollector
    {
        private readonly INetworkSnapshotCollector networkCollector;
        private readonly ISysmonEventCollector sysmonCollector;
        private readonly IHostTelemetryCollector hostTelemetryCollector;
        private readonly FileLogger logger;
        private readonly HashSet<string> warnedCollectors = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        public CompositeNetworkSnapshotCollector(INetworkSnapshotCollector networkCollector, ISysmonEventCollector sysmonCollector, IHostTelemetryCollector hostTelemetryCollector, FileLogger logger)
        {
            this.networkCollector = networkCollector;
            this.sysmonCollector = sysmonCollector;
            this.hostTelemetryCollector = hostTelemetryCollector;
            this.logger = logger;
        }

        public NetworkSnapshot Capture()
        {
            NetworkSnapshot networkSnapshot = CaptureNetworkSnapshot();
            SysmonTelemetry sysmon = CaptureSysmonTelemetry();
            HostTelemetry hostTelemetry = CaptureHostTelemetry();

            List<NetworkEndpoint> endpoints = new List<NetworkEndpoint>(networkSnapshot.Endpoints);
            endpoints.AddRange(sysmon.NetworkConnections);

            return new NetworkSnapshot(endpoints, sysmon.DnsQueries, sysmon.ProcessEvents, sysmon.FileEvents, hostTelemetry);
        }

        private NetworkSnapshot CaptureNetworkSnapshot()
        {
            if (networkCollector == null) return new NetworkSnapshot(new List<NetworkEndpoint>());

            try
            {
                NetworkSnapshot snapshot = networkCollector.Capture();
                return snapshot ?? new NetworkSnapshot(new List<NetworkEndpoint>());
            }
            catch (Exception ex)
            {
                WarnOnce("netstat", "Network collector failed; continuing with remaining telemetry: " + ex.Message);
                return new NetworkSnapshot(new List<NetworkEndpoint>());
            }
        }

        private SysmonTelemetry CaptureSysmonTelemetry()
        {
            if (sysmonCollector == null) return new SysmonTelemetry();

            try
            {
                SysmonTelemetry telemetry = sysmonCollector.Capture();
                return telemetry ?? new SysmonTelemetry();
            }
            catch (Exception ex)
            {
                WarnOnce("sysmon", "Sysmon collector failed; continuing with remaining telemetry: " + ex.Message);
                return new SysmonTelemetry();
            }
        }

        private HostTelemetry CaptureHostTelemetry()
        {
            if (hostTelemetryCollector == null) return new HostTelemetry();

            try
            {
                HostTelemetry telemetry = hostTelemetryCollector.Capture();
                return telemetry ?? new HostTelemetry();
            }
            catch (Exception ex)
            {
                WarnOnce("host", "Host telemetry collector failed; continuing with network telemetry: " + ex.Message);
                return new HostTelemetry();
            }
        }

        private void WarnOnce(string collectorName, string message)
        {
            if (logger == null || warnedCollectors.Contains(collectorName)) return;
            warnedCollectors.Add(collectorName);
            logger.Warn(message);
        }
    }
}
