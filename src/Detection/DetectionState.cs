using System.Collections.Generic;

namespace ArcaneEDR
{
    internal sealed class DetectionState
    {
        private readonly HashSet<string> seenConnections = new HashSet<string>(System.StringComparer.OrdinalIgnoreCase);
        private readonly HashSet<string> seenListeners = new HashSet<string>(System.StringComparer.OrdinalIgnoreCase);
        private readonly HashSet<string> seenEvents = new HashSet<string>(System.StringComparer.OrdinalIgnoreCase);

        public DetectionState()
        {
            BeaconTracker = new BeaconTracker();
        }

        public BeaconTracker BeaconTracker { get; private set; }

        public bool MarkConnectionSeen(string key)
        {
            if (seenConnections.Contains(key)) return false;
            seenConnections.Add(key);
            return true;
        }

        public bool MarkListenerSeen(string key)
        {
            if (seenListeners.Contains(key)) return false;
            seenListeners.Add(key);
            return true;
        }

        public bool MarkEventSeen(string key)
        {
            if (seenEvents.Contains(key)) return false;
            seenEvents.Add(key);
            return true;
        }
    }
}
