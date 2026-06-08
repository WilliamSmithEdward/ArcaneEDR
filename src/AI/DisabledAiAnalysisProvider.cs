using System;

namespace ArcaneEDR
{
    internal sealed class DisabledAiAnalysisProvider : IAiAnalysisProvider
    {
        private readonly string reason;

        public DisabledAiAnalysisProvider(string reason)
        {
            this.reason = String.IsNullOrWhiteSpace(reason) ? "AI analysis is disabled." : reason;
        }

        public string ProviderName
        {
            get { return "Disabled"; }
        }

        public bool IsConfigured
        {
            get { return false; }
        }

        public string MissingConfigurationReason
        {
            get { return reason; }
        }

        public AiAnalysisResult Analyze(string compactLogPayload)
        {
            throw new InvalidOperationException(reason);
        }

        public AiAnalysisResult AnalyzeDailyReport(string dailyReportPayload)
        {
            throw new InvalidOperationException(reason);
        }
    }
}
