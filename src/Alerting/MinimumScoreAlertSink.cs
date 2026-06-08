using System.Globalization;

namespace ArcaneEDR
{
    internal sealed class MinimumScoreAlertSink : IAlertSink
    {
        private readonly string providerName;
        private readonly int minimumScore;
        private readonly IAlertSink inner;
        private readonly FileLogger logger;

        public MinimumScoreAlertSink(string providerName, int minimumScore, IAlertSink inner, FileLogger logger)
        {
            this.providerName = providerName;
            this.minimumScore = minimumScore;
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

        public void Send(Alert alert)
        {
            if (alert != null && alert.Score < minimumScore)
            {
                logger.Info("Skipping alert sink " + providerName +
                    " because alert score " + alert.Score.ToString(CultureInfo.InvariantCulture) +
                    " is below provider minimum " + minimumScore.ToString(CultureInfo.InvariantCulture) + ".");
                return;
            }

            inner.Send(alert);
        }
    }
}
