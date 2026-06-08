using System;
using System.Collections.Generic;

namespace ArcaneEDR
{
    internal static class AlertSinkFactory
    {
        public static IAlertSink Create(MonitorConfig config, FileLogger logger)
        {
            List<IAlertSink> sinks = new List<IAlertSink>();
            ISecretProvider secretProvider = new EnvironmentSecretProvider();
            foreach (string provider in config.GetExternalAlertProviders())
            {
                if (provider.Equals("Disabled", StringComparison.OrdinalIgnoreCase) ||
                    provider.Equals("None", StringComparison.OrdinalIgnoreCase) ||
                    provider.Equals("Off", StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }

                if (provider.Equals("Brevo", StringComparison.OrdinalIgnoreCase))
                {
                    BrevoTransactionalEmailClient client = new BrevoTransactionalEmailClient(config, secretProvider);
                    sinks.Add(ApplyProviderMinimum(config, logger, provider, new BrevoEmailAlertSink(config, logger, client)));
                }
                else if (provider.Equals("Smtp", StringComparison.OrdinalIgnoreCase) ||
                    provider.Equals("SmtpEmail", StringComparison.OrdinalIgnoreCase) ||
                    provider.Equals("SmtpEmailAlertSink", StringComparison.OrdinalIgnoreCase))
                {
                    sinks.Add(ApplyProviderMinimum(config, logger, provider, new SmtpEmailAlertSink(config, logger, secretProvider)));
                }
                else if (provider.Equals("Webhook", StringComparison.OrdinalIgnoreCase) ||
                    provider.Equals("WebhookAlertSink", StringComparison.OrdinalIgnoreCase))
                {
                    sinks.Add(ApplyProviderMinimum(config, logger, provider, new HttpJsonAlertSink(
                        "Webhook",
                        config.WebhookAlertUrl,
                        config.WebhookSecretEnvironmentVariable,
                        config.WebhookSecretHeaderName,
                        config.WebhookSecretPrefix,
                        config.WebhookTimeoutSeconds,
                        logger,
                        secretProvider)));
                }
                else if (provider.Equals("GenericHttpApi", StringComparison.OrdinalIgnoreCase) ||
                    provider.Equals("GenericHttpApiAlertSink", StringComparison.OrdinalIgnoreCase) ||
                    provider.Equals("HttpApi", StringComparison.OrdinalIgnoreCase))
                {
                    sinks.Add(ApplyProviderMinimum(config, logger, provider, new HttpJsonAlertSink(
                        "Generic HTTP API",
                        config.GenericHttpApiAlertUrl,
                        config.GenericHttpApiSecretEnvironmentVariable,
                        config.GenericHttpApiSecretHeaderName,
                        config.GenericHttpApiSecretPrefix,
                        config.GenericHttpApiTimeoutSeconds,
                        logger,
                        secretProvider)));
                }
                else if (provider.Equals("LocalJsonl", StringComparison.OrdinalIgnoreCase) ||
                    provider.Equals("LocalJsonlAlertSink", StringComparison.OrdinalIgnoreCase))
                {
                    sinks.Add(ApplyProviderMinimum(config, logger, provider, new LocalJsonlAlertSink(config, logger)));
                }
                else if (provider.Equals("WindowsEventLog", StringComparison.OrdinalIgnoreCase) ||
                    provider.Equals("EventLog", StringComparison.OrdinalIgnoreCase) ||
                    provider.Equals("WindowsEventLogAlertSink", StringComparison.OrdinalIgnoreCase))
                {
                    sinks.Add(ApplyProviderMinimum(config, logger, provider, new WindowsEventLogAlertSink(config, logger)));
                }
                else
                {
                    sinks.Add(new DisabledAlertSink("Unsupported external alert provider: " + provider));
                }
            }

            if (sinks.Count == 0)
            {
                return new DisabledAlertSink("External alert delivery is disabled. Alerts are written to local logs only.");
            }

            if (sinks.Count == 1)
            {
                return sinks[0];
            }

            return new CompositeAlertSink(sinks, logger);
        }

        private static IAlertSink ApplyProviderMinimum(MonitorConfig config, FileLogger logger, string provider, IAlertSink sink)
        {
            int minimumScore = config.ExternalAlertProviderMinimumScore(provider);
            if (minimumScore <= 0) return sink;

            return new MinimumScoreAlertSink(
                MonitorConfig.CanonicalExternalAlertProvider(provider),
                minimumScore,
                sink,
                logger);
        }
    }
}
