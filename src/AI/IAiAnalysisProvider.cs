namespace ArcaneEDR
{
    internal interface IAiAnalysisProvider
    {
        string ProviderName { get; }
        bool IsConfigured { get; }
        string MissingConfigurationReason { get; }
        OpenAiAnalysisResult Analyze(string compactLogPayload);
        OpenAiAnalysisResult AnalyzeDailyReport(string dailyReportPayload);
    }
}
