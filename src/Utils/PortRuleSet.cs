using System;
using System.Collections.Generic;

namespace ArcaneEDR
{
    internal sealed class PortRuleSet
    {
        private readonly List<PortRange> ranges = new List<PortRange>();

        public void Add(string value)
        {
            if (String.IsNullOrWhiteSpace(value)) return;

            string[] parts = value.Split('-');
            int start;
            int end;
            if (parts.Length == 1)
            {
                if (!Int32.TryParse(parts[0], out start)) return;
                end = start;
            }
            else if (parts.Length == 2)
            {
                if (!Int32.TryParse(parts[0], out start)) return;
                if (!Int32.TryParse(parts[1], out end)) return;
            }
            else
            {
                return;
            }

            if (start < 0 || end > 65535 || start > end) return;
            ranges.Add(new PortRange(start, end));
        }

        public bool Contains(int port)
        {
            foreach (PortRange range in ranges)
            {
                if (port >= range.Start && port <= range.End) return true;
            }

            return false;
        }

        public int Count
        {
            get { return ranges.Count; }
        }
    }

    internal sealed class PortRange
    {
        public readonly int Start;
        public readonly int End;

        public PortRange(int start, int end)
        {
            Start = start;
            End = end;
        }
    }
}
