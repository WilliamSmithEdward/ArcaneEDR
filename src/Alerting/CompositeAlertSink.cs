using System;
using System.Collections.Generic;

namespace ArcaneEDR
{
    internal sealed class CompositeAlertSink : IAlertSink
    {
        private readonly List<IAlertSink> sinks;
        private readonly FileLogger logger;

        public CompositeAlertSink(IEnumerable<IAlertSink> sinks, FileLogger logger)
        {
            this.sinks = new List<IAlertSink>(sinks);
            this.logger = logger;
        }

        public bool IsConfigured
        {
            get
            {
                foreach (IAlertSink sink in sinks)
                {
                    if (sink.IsConfigured) return true;
                }

                return false;
            }
        }

        public string MissingConfigurationReason
        {
            get
            {
                List<string> reasons = new List<string>();
                foreach (IAlertSink sink in sinks)
                {
                    if (!sink.IsConfigured && !String.IsNullOrWhiteSpace(sink.MissingConfigurationReason))
                    {
                        reasons.Add(sink.GetType().Name + ": " + sink.MissingConfigurationReason);
                    }
                }

                return reasons.Count == 0 ? "No configured alert sinks." : String.Join("; ", reasons.ToArray());
            }
        }

        public void Send(Alert alert)
        {
            int configured = 0;
            int sent = 0;
            List<string> failures = new List<string>();

            foreach (IAlertSink sink in sinks)
            {
                if (!sink.IsConfigured)
                {
                    logger.Warn("Skipping unconfigured alert sink " + sink.GetType().Name + ": " + sink.MissingConfigurationReason);
                    continue;
                }

                configured++;
                try
                {
                    sink.Send(alert);
                    sent++;
                }
                catch (Exception ex)
                {
                    string failure = sink.GetType().Name + ": " + ex.Message;
                    failures.Add(failure);
                    logger.Error("Alert sink failed: " + failure);
                }
            }

            if (sent > 0)
            {
                if (failures.Count > 0)
                {
                    logger.Warn("Alert delivered to " + sent + " of " + configured + " configured sink(s); failures: " + String.Join("; ", failures.ToArray()));
                }

                return;
            }

            if (configured == 0)
            {
                throw new InvalidOperationException(MissingConfigurationReason);
            }

            throw new InvalidOperationException("All configured alert sinks failed: " + String.Join("; ", failures.ToArray()));
        }
    }
}
