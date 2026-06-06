namespace ArcaneEDR
{
    internal interface IAlertSink
    {
        bool IsConfigured { get; }
        string MissingConfigurationReason { get; }
        void Send(Alert alert);
    }
}
