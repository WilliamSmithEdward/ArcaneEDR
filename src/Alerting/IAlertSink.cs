namespace ArcaneEDR
{
    internal interface IAlertSink
    {
        bool IsConfigured { get; }
        string MissingConfigurationReason { get; }
        bool Send(Alert alert);
    }
}
