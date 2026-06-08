using System;
using System.Globalization;
using System.Net;
using System.Net.Mail;

namespace ArcaneEDR
{
    internal sealed class SmtpEmailAlertSink : IAlertSink
    {
        private readonly MonitorConfig config;
        private readonly FileLogger logger;
        private readonly ISecretProvider secretProvider;

        public SmtpEmailAlertSink(MonitorConfig config, FileLogger logger, ISecretProvider secretProvider)
        {
            this.config = config;
            this.logger = logger;
            this.secretProvider = secretProvider;
        }

        public bool IsConfigured
        {
            get
            {
                if (!config.HasSmtpEmailConfig) return false;
                if (String.IsNullOrWhiteSpace(config.SmtpPasswordEnvironmentVariable)) return true;
                return !String.IsNullOrWhiteSpace(secretProvider.GetSecret(config.SmtpPasswordEnvironmentVariable));
            }
        }

        public string MissingConfigurationReason
        {
            get
            {
                if (!config.HasSmtpEmailConfig)
                {
                    return "SMTP host, sender email, or recipient email is missing.";
                }

                if (!String.IsNullOrWhiteSpace(config.SmtpPasswordEnvironmentVariable) &&
                    String.IsNullOrWhiteSpace(secretProvider.GetSecret(config.SmtpPasswordEnvironmentVariable)))
                {
                    return "SMTP password environment variable is not visible: " + config.SmtpPasswordEnvironmentVariable;
                }

                return "";
            }
        }

        public bool Send(Alert alert)
        {
            using (MailMessage message = new MailMessage())
            {
                message.From = new MailAddress(config.SmtpSenderEmail, config.SmtpSenderName);
                message.To.Add(new MailAddress(config.SmtpRecipientEmail, config.SmtpRecipientName));
                message.Subject = AlertMessageFormatter.BuildSubject(alert);
                message.Body = AlertMessageFormatter.BuildHtml(alert);
                message.IsBodyHtml = true;

                using (SmtpClient client = new SmtpClient(config.SmtpHost, config.SmtpPort))
                {
                    client.EnableSsl = config.SmtpEnableSsl;
                    client.Timeout = config.SmtpTimeoutSeconds <= 0 ? 15000 : config.SmtpTimeoutSeconds * 1000;
                    ConfigureCredentials(client);
                    client.Send(message);
                }
            }

            logger.Info("Sent SMTP alert for " + alert.RuleId +
                " score=" + alert.Score.ToString(CultureInfo.InvariantCulture) +
                " host=" + config.SmtpHost +
                " port=" + config.SmtpPort.ToString(CultureInfo.InvariantCulture));
            return true;
        }

        private void ConfigureCredentials(SmtpClient client)
        {
            if (String.IsNullOrWhiteSpace(config.SmtpUsername) &&
                String.IsNullOrWhiteSpace(config.SmtpPasswordEnvironmentVariable))
            {
                client.UseDefaultCredentials = false;
                return;
            }

            string password = String.IsNullOrWhiteSpace(config.SmtpPasswordEnvironmentVariable)
                ? ""
                : secretProvider.GetSecret(config.SmtpPasswordEnvironmentVariable);
            client.UseDefaultCredentials = false;
            client.Credentials = new NetworkCredential(config.SmtpUsername, password);
        }
    }
}
