using System;
using System.Collections.Generic;

namespace ArcaneEDR
{
    internal static class AiAnalysisProviderFactory
    {
        public static IAiAnalysisProvider Create(MonitorConfig config, FileLogger logger, ISecretProvider secretProvider)
        {
            List<IAiAnalysisProvider> providers = new List<IAiAnalysisProvider>();
            foreach (string providerName in config.GetAiAnalysisProviderNames())
            {
                providers.Add(CreateSingle(config, logger, secretProvider, providerName));
            }

            if (providers.Count == 0)
            {
                return new DisabledAiAnalysisProvider("AI analysis providers are disabled or empty.");
            }

            if (providers.Count == 1)
            {
                return providers[0];
            }

            return new CompositeAiAnalysisProvider(providers, logger);
        }

        private static IAiAnalysisProvider CreateSingle(MonitorConfig config, FileLogger logger, ISecretProvider secretProvider, string providerName)
        {
            AiAnalysisProviderSettings settings = config.AiAnalysisSettingsFor(providerName);
            if (settings.ProviderType.Equals("Disabled", StringComparison.OrdinalIgnoreCase))
            {
                return new DisabledAiAnalysisProvider("AI analysis provider is disabled: " + providerName);
            }

            if (settings.ProviderType.Equals("OpenAI", StringComparison.OrdinalIgnoreCase) ||
                settings.ProviderType.Equals("OpenAICompatible", StringComparison.OrdinalIgnoreCase))
            {
                return new OpenAiCompatibleAnalysisProvider(config, logger, secretProvider, settings);
            }

            if (settings.ProviderType.Equals("Anthropic", StringComparison.OrdinalIgnoreCase))
            {
                return new AnthropicAnalysisProvider(config, logger, secretProvider, settings);
            }

            return new DisabledAiAnalysisProvider("Unsupported AI analysis provider: " + providerName);
        }
    }
}
