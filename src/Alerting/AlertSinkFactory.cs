using System;

namespace ArcaneEDR
{
    internal static class AlertSinkFactory
    {
        public static IAlertSink Create(MonitorConfig config, FileLogger logger)
        {
            if (config.ExternalAlertProvider.Equals("Brevo", StringComparison.OrdinalIgnoreCase))
            {
                ISecretProvider secretProvider = new EnvironmentSecretProvider();
                BrevoTransactionalEmailClient client = new BrevoTransactionalEmailClient(config, secretProvider);
                return new BrevoEmailAlertSink(config, logger, client);
            }

            return new DisabledAlertSink("External email delivery is disabled. Alerts are written to local logs only.");
        }
    }
}
