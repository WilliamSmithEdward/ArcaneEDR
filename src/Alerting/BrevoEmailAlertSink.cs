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

        public void Send(Alert alert)
        {
            BrevoEmailMessage message = new BrevoEmailMessage
            {
                SenderEmail = config.BrevoSenderEmail,
                SenderName = config.BrevoSenderName,
                RecipientEmail = config.BrevoRecipientEmail,
                RecipientName = config.BrevoRecipientName,
                Subject = "[Arcane EDR][" + alert.Severity + "][" + alert.RuleId + "] " + alert.Title,
                HtmlContent = BuildHtml(alert)
            };

            BrevoSendResult result = client.Send(message);
            logger.Info("Sent Brevo alert for " + alert.RuleId + " score=" + alert.Score.ToString(CultureInfo.InvariantCulture) + " status=" + result.StatusCode.ToString(CultureInfo.InvariantCulture));
        }

        private static string BuildHtml(Alert alert)
        {
            return "<html><body>" +
                "<h2>" + HtmlEscape(alert.Title) + "</h2>" +
                "<p><strong>Rule:</strong> " + HtmlEscape(alert.RuleId) + "</p>" +
                "<p><strong>Severity:</strong> " + HtmlEscape(alert.Severity) + "</p>" +
                "<p><strong>Score:</strong> " + alert.Score.ToString(CultureInfo.InvariantCulture) + "</p>" +
                "<p><strong>UTC:</strong> " + HtmlEscape(alert.TimestampUtc.ToString("yyyy-MM-ddTHH:mm:ssZ", CultureInfo.InvariantCulture)) + "</p>" +
                "<h3>Details</h3><pre>" + HtmlEscape(alert.Body) + "</pre>" +
                "<h3>Recommendation</h3><pre>" + HtmlEscape(alert.Recommendation) + "</pre>" +
                "<h3>Entity</h3><pre>" + HtmlEscape(alert.EntitySummary) + "</pre>" +
                "</body></html>";
        }

        private static string HtmlEscape(string value)
        {
            if (value == null) return "";
            return value
                .Replace("&", "&amp;")
                .Replace("<", "&lt;")
                .Replace(">", "&gt;")
                .Replace("\"", "&quot;");
        }
    }
}
