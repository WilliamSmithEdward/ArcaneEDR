using System;
using System.Globalization;
using System.IO;
using System.Net;
using System.Text;

namespace ArcaneEDR
{
    internal sealed class DailyReportHttpSink
    {
        private readonly MonitorConfig config;
        private readonly FileLogger logger;
        private readonly ISecretProvider secretProvider;

        public DailyReportHttpSink(MonitorConfig config, FileLogger logger, ISecretProvider secretProvider)
        {
            this.config = config;
            this.logger = logger;
            this.secretProvider = secretProvider;
        }

        public bool IsConfigured
        {
            get
            {
                if (String.IsNullOrWhiteSpace(config.DailyReportWebhookUrl)) return false;
                if (String.IsNullOrWhiteSpace(config.DailyReportWebhookSecretEnvironmentVariable)) return true;
                return !String.IsNullOrWhiteSpace(secretProvider.GetSecret(config.DailyReportWebhookSecretEnvironmentVariable));
            }
        }

        public string MissingConfigurationReason
        {
            get
            {
                if (String.IsNullOrWhiteSpace(config.DailyReportWebhookUrl)) return "DailyReportWebhookUrl is empty.";
                if (!String.IsNullOrWhiteSpace(config.DailyReportWebhookSecretEnvironmentVariable) &&
                    String.IsNullOrWhiteSpace(secretProvider.GetSecret(config.DailyReportWebhookSecretEnvironmentVariable)))
                {
                    return "Daily report webhook secret environment variable is not visible: " + config.DailyReportWebhookSecretEnvironmentVariable;
                }

                return "";
            }
        }

        public void Send(DailyReportSnapshot snapshot, string jsonReport)
        {
            ServicePointManager.SecurityProtocol = ServicePointManager.SecurityProtocol | (SecurityProtocolType)3072;

            byte[] body = Encoding.UTF8.GetBytes(String.IsNullOrWhiteSpace(jsonReport) ? "{}" : jsonReport);
            HttpWebRequest request = (HttpWebRequest)WebRequest.Create(config.DailyReportWebhookUrl);
            request.Method = "POST";
            request.ContentType = "application/json";
            request.Accept = "application/json";
            request.Timeout = config.DailyReportWebhookTimeoutSeconds * 1000;
            request.ReadWriteTimeout = config.DailyReportWebhookTimeoutSeconds * 1000;

            AddSecretHeader(request);

            using (Stream stream = request.GetRequestStream())
            {
                stream.Write(body, 0, body.Length);
            }

            using (HttpWebResponse response = (HttpWebResponse)request.GetResponse())
            {
                logger.Info("Sent daily report webhook generated_utc=" +
                    (snapshot == null ? "" : UtcTimestamp.Format(snapshot.GeneratedUtc)) +
                    " status=" + ((int)response.StatusCode).ToString(CultureInfo.InvariantCulture) +
                    " response=" + AlertMessageFormatter.Compact(HttpResponseText.Read(response), 300));
            }
        }

        private void AddSecretHeader(HttpWebRequest request)
        {
            if (String.IsNullOrWhiteSpace(config.DailyReportWebhookSecretEnvironmentVariable)) return;
            if (String.IsNullOrWhiteSpace(config.DailyReportWebhookSecretHeaderName)) return;

            string secret = secretProvider.GetSecret(config.DailyReportWebhookSecretEnvironmentVariable);
            if (String.IsNullOrWhiteSpace(secret)) return;

            string value = HttpAuthHeader.NormalizePrefix(config.DailyReportWebhookSecretPrefix) + secret;
            if (config.DailyReportWebhookSecretHeaderName.Equals("Authorization", StringComparison.OrdinalIgnoreCase))
            {
                request.Headers[HttpRequestHeader.Authorization] = value;
            }
            else
            {
                request.Headers[config.DailyReportWebhookSecretHeaderName] = value;
            }
        }

    }
}
