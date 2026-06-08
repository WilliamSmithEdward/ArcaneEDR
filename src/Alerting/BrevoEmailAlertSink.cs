using System;
using System.Globalization;

namespace ArcaneEDR
{
    internal sealed class BrevoEmailAlertSink : IAlertSink
    {
        private readonly MonitorConfig config;
        private readonly FileLogger logger;
        private readonly BrevoTransactionalEmailClient client;

        public BrevoEmailAlertSink(MonitorConfig config, FileLogger logger, BrevoTransactionalEmailClient client)
        {
            this.config = config;
            this.logger = logger;
            this.client = client;
        }

        public bool IsConfigured
        {
            get { return config.HasBrevoEmailConfig && client.HasApiKey; }
        }

        public string MissingConfigurationReason
        {
            get
            {
                if (!config.HasBrevoEmailConfig)
                {
                    return "Brevo API URL, sender email, recipient email, or API key environment variable name is missing.";
                }

                if (!client.HasApiKey)
                {
                    return "Environment variable '" + config.BrevoApiKeyEnvironmentVariable + "' was not found in Process, User, or Machine scope.";
                }

                return "";
            }
        }

        public bool Send(Alert alert)
        {
            BrevoEmailMessage message = new BrevoEmailMessage
            {
                SenderEmail = config.BrevoSenderEmail,
                SenderName = config.BrevoSenderName,
                RecipientEmail = config.BrevoRecipientEmail,
                RecipientName = config.BrevoRecipientName,
                Subject = AlertMessageFormatter.BuildSubject(alert),
                HtmlContent = AlertMessageFormatter.BuildHtml(alert)
            };

            BrevoSendResult result = client.Send(message);
            logger.Info("Sent Brevo alert for " + alert.RuleId +
                " score=" + alert.Score.ToString(CultureInfo.InvariantCulture) +
                " status=" + result.StatusCode.ToString(CultureInfo.InvariantCulture) +
                " response=" + AlertMessageFormatter.Compact(result.ResponseBody, 300));
            return true;
        }
    }
}
