using System;
using System.Collections.Generic;

namespace ArcaneEDR
{
    internal sealed class CompositeHostTelemetryCollector : IHostTelemetryCollector
    {
        private readonly List<IHostTelemetryCollector> collectors;
        private readonly FileLogger logger;
        private readonly HashSet<string> warnedCollectors = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        public CompositeHostTelemetryCollector(IEnumerable<IHostTelemetryCollector> collectors, FileLogger logger)
        {
            this.collectors = new List<IHostTelemetryCollector>(collectors);
            this.logger = logger;
        }

        public HostTelemetry Capture()
        {
            HostTelemetry combined = new HostTelemetry();

            foreach (IHostTelemetryCollector collector in collectors)
            {
                HostTelemetry telemetry = CaptureCollector(collector);
                combined.PowerShellEvents.AddRange(telemetry.PowerShellEvents);
                combined.WindowsEvents.AddRange(telemetry.WindowsEvents);
                combined.PersistenceItems.AddRange(telemetry.PersistenceItems);
            }

            return combined;
        }

        private HostTelemetry CaptureCollector(IHostTelemetryCollector collector)
        {
            if (collector == null) return new HostTelemetry();

            try
            {
                HostTelemetry telemetry = collector.Capture();
                return telemetry ?? new HostTelemetry();
            }
            catch (Exception ex)
            {
                string collectorName = collector.GetType().Name;
                if (logger != null && !warnedCollectors.Contains(collectorName))
                {
                    warnedCollectors.Add(collectorName);
                    logger.Warn(collectorName + " failed; continuing with remaining host telemetry: " + ex.Message);
                }

                return new HostTelemetry();
            }
        }
    }
}
