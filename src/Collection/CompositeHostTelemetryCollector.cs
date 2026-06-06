using System.Collections.Generic;

namespace ArcaneEDR
{
    internal sealed class CompositeHostTelemetryCollector : IHostTelemetryCollector
    {
        private readonly List<IHostTelemetryCollector> collectors;

        public CompositeHostTelemetryCollector(IEnumerable<IHostTelemetryCollector> collectors)
        {
            this.collectors = new List<IHostTelemetryCollector>(collectors);
        }

        public HostTelemetry Capture()
        {
            HostTelemetry combined = new HostTelemetry();

            foreach (IHostTelemetryCollector collector in collectors)
            {
                HostTelemetry telemetry = collector.Capture();
                combined.PowerShellEvents.AddRange(telemetry.PowerShellEvents);
                combined.WindowsEvents.AddRange(telemetry.WindowsEvents);
                combined.PersistenceItems.AddRange(telemetry.PersistenceItems);
            }

            return combined;
        }
    }
}
