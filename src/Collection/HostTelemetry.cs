using System.Collections.Generic;

namespace ArcaneEDR
{
    internal sealed class HostTelemetry
    {
        public HostTelemetry()
        {
            PowerShellEvents = new List<PowerShellEvent>();
            WindowsEvents = new List<WindowsAuditEvent>();
            PersistenceItems = new List<PersistenceItem>();
        }

        public List<PowerShellEvent> PowerShellEvents { get; private set; }
        public List<WindowsAuditEvent> WindowsEvents { get; private set; }
        public List<PersistenceItem> PersistenceItems { get; private set; }
    }
}
