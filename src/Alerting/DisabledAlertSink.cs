namespace ArcaneEDR
{
    internal sealed class DisabledAlertSink : IAlertSink
    {
        public DisabledAlertSink(string reason)
        {
            MissingConfigurationReason = reason;
        }

        public bool IsConfigured
        {
            get { return false; }
        }

        public string MissingConfigurationReason { get; private set; }

        public void Send(Alert alert)
        {
        }
    }
}
