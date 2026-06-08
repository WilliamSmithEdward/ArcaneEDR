using System;

namespace ArcaneEDR
{
    internal static class AiAnalysisProviderFactory
    {
        public static IAiAnalysisProvider Create(MonitorConfig config, FileLogger logger, ISecretProvider secretProvider)
        {
            string provider = MonitorConfig.CanonicalAiAnalysisProvider(config.AIAnalysisProvider);
            if (provider.Equals("Disabled", StringComparison.OrdinalIgnoreCase))
            {
                return new DisabledAiAnalysisProvider("AI analysis provider is disabled.");
            }

            if (provider.Equals("OpenAI", StringComparison.OrdinalIgnoreCase) ||
                provider.Equals("OpenAICompatible", StringComparison.OrdinalIgnoreCase))
            {
                return new OpenAiCompatibleAnalysisProvider(config, logger, secretProvider, provider);
            }

            return new DisabledAiAnalysisProvider("Unsupported AI analysis provider: " + config.AIAnalysisProvider);
        }
    }
}
