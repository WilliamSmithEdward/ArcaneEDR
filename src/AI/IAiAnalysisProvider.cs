namespace ArcaneEDR
{
    internal interface IAiAnalysisProvider
    {
        string ProviderName { get; }
        bool IsConfigured { get; }
        string MissingConfigurationReason { get; }
        AiAnalysisResult Analyze(string compactLogPayload);
        AiAnalysisResult AnalyzeDailyReport(string dailyReportPayload);
    }
}
