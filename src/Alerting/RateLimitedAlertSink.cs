using System;
using System.Collections.Generic;
using System.Globalization;

namespace ArcaneEDR
{
    internal sealed class RateLimitedAlertSink : IAlertSink
    {
        private readonly string providerName;
        private readonly int maxPerHour;
        private readonly IAlertSink inner;
        private readonly FileLogger logger;
        private readonly Queue<DateTime> sends = new Queue<DateTime>();

        public RateLimitedAlertSink(string providerName, int maxPerHour, IAlertSink inner, FileLogger logger)
        {
            this.providerName = providerName;
            this.maxPerHour = maxPerHour;
            this.inner = inner;
            this.logger = logger;
        }

        public bool IsConfigured
        {
            get { return inner.IsConfigured; }
        }

        public string MissingConfigurationReason
        {
            get { return inner.MissingConfigurationReason; }
        }

        public bool Send(Alert alert)
        {
            Prune();
            if (maxPerHour > 0 && sends.Count >= maxPerHour)
            {
                logger.Warn("Skipping alert sink " + providerName +
                    " because provider hourly limit " + maxPerHour.ToString(CultureInfo.InvariantCulture) +
                    " has been reached.");
                return false;
            }

            if (!inner.Send(alert))
            {
                return false;
            }

            sends.Enqueue(DateTime.UtcNow);
            Prune();
            return true;
        }

        private void Prune()
        {
            DateTime cutoff = DateTime.UtcNow.AddHours(-1);
            while (sends.Count > 0 && sends.Peek() < cutoff)
            {
                sends.Dequeue();
            }
        }
    }
}
