using System;
using System.Globalization;
using System.IO;
using System.Net;
using System.Text;

namespace ArcaneEDR
{
    internal sealed class HttpJsonAlertSink : IAlertSink
    {
        private readonly string name;
        private readonly string url;
        private readonly string secretEnvironmentVariable;
        private readonly string secretHeaderName;
        private readonly string secretPrefix;
        private readonly int timeoutSeconds;
        private readonly FileLogger logger;
        private readonly ISecretProvider secretProvider;

        public HttpJsonAlertSink(
            string name,
            string url,
            string secretEnvironmentVariable,
            string secretHeaderName,
            string secretPrefix,
            int timeoutSeconds,
            FileLogger logger,
            ISecretProvider secretProvider)
        {
            this.name = name;
            this.url = url;
            this.secretEnvironmentVariable = secretEnvironmentVariable;
            this.secretHeaderName = secretHeaderName;
            this.secretPrefix = NormalizePrefix(secretPrefix);
            this.timeoutSeconds = timeoutSeconds <= 0 ? 15 : timeoutSeconds;
            this.logger = logger;
            this.secretProvider = secretProvider;
        }

        public bool IsConfigured
        {
            get
            {
                if (String.IsNullOrWhiteSpace(url)) return false;
                if (String.IsNullOrWhiteSpace(secretEnvironmentVariable)) return true;
                return !String.IsNullOrWhiteSpace(secretProvider.GetSecret(secretEnvironmentVariable));
            }
        }

        public string MissingConfigurationReason
        {
            get
            {
                if (String.IsNullOrWhiteSpace(url)) return name + " URL is empty.";
                if (!String.IsNullOrWhiteSpace(secretEnvironmentVariable) &&
                    String.IsNullOrWhiteSpace(secretProvider.GetSecret(secretEnvironmentVariable)))
                {
                    return name + " secret environment variable is not visible: " + secretEnvironmentVariable;
                }

                return "";
            }
        }

        public void Send(Alert alert)
        {
            byte[] body = Encoding.UTF8.GetBytes(alert.ToJson());
            HttpWebRequest request = (HttpWebRequest)WebRequest.Create(url);
            request.Method = "POST";
            request.ContentType = "application/json";
            request.Accept = "application/json";
            request.Timeout = timeoutSeconds * 1000;
            request.ReadWriteTimeout = timeoutSeconds * 1000;

            AddSecretHeader(request);

            using (Stream stream = request.GetRequestStream())
            {
                stream.Write(body, 0, body.Length);
            }

            using (HttpWebResponse response = (HttpWebResponse)request.GetResponse())
            {
                logger.Info("Sent " + name + " alert for " + alert.RuleId +
                    " score=" + alert.Score.ToString(CultureInfo.InvariantCulture) +
                    " status=" + ((int)response.StatusCode).ToString(CultureInfo.InvariantCulture) +
                    " response=" + AlertMessageFormatter.Compact(ReadResponse(response), 300));
            }
        }

        private void AddSecretHeader(HttpWebRequest request)
        {
            if (String.IsNullOrWhiteSpace(secretEnvironmentVariable)) return;
            if (String.IsNullOrWhiteSpace(secretHeaderName)) return;

            string secret = secretProvider.GetSecret(secretEnvironmentVariable);
            if (String.IsNullOrWhiteSpace(secret)) return;

            string value = secretPrefix + secret;
            if (secretHeaderName.Equals("Authorization", StringComparison.OrdinalIgnoreCase))
            {
                request.Headers[HttpRequestHeader.Authorization] = value;
            }
            else
            {
                request.Headers[secretHeaderName] = value;
            }
        }

        private static string ReadResponse(HttpWebResponse response)
        {
            using (Stream stream = response.GetResponseStream())
            using (StreamReader reader = new StreamReader(stream))
            {
                return reader.ReadToEnd();
            }
        }

        private static string NormalizePrefix(string prefix)
        {
            if (String.IsNullOrWhiteSpace(prefix)) return "";
            string trimmed = prefix.Trim();
            if (trimmed.Equals("Bearer", StringComparison.OrdinalIgnoreCase) ||
                trimmed.Equals("Token", StringComparison.OrdinalIgnoreCase))
            {
                return trimmed + " ";
            }

            return prefix;
        }
    }
}
