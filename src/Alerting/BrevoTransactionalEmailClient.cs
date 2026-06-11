using System;
using System.Globalization;
using System.IO;
using System.Net;
using System.Text;

namespace ArcaneEDR
{
    internal sealed class BrevoTransactionalEmailClient
    {
        private readonly MonitorConfig config;
        private readonly ISecretProvider secretProvider;

        public BrevoTransactionalEmailClient(MonitorConfig config, ISecretProvider secretProvider)
        {
            this.config = config;
            this.secretProvider = secretProvider;
        }

        public bool HasApiKey
        {
            get { return !String.IsNullOrWhiteSpace(GetApiKey()); }
        }

        public BrevoSendResult Send(BrevoEmailMessage message)
        {
            string apiKey = GetApiKey();
            if (String.IsNullOrWhiteSpace(apiKey))
            {
                throw new InvalidOperationException("Brevo API key is missing.");
            }

            ServicePointManager.SecurityProtocol = ServicePointManager.SecurityProtocol | (SecurityProtocolType)3072;

            byte[] body = Encoding.UTF8.GetBytes(BuildPayload(message));
            HttpWebRequest request = (HttpWebRequest)WebRequest.Create(config.BrevoApiUrl);
            request.Method = "POST";
            request.Accept = "application/json";
            request.ContentType = "application/json";
            request.Headers["api-key"] = apiKey;
            request.ContentLength = body.Length;
            request.Timeout = HttpResponseText.TimeoutMilliseconds(config.BrevoTimeoutSeconds, 15);
            request.ReadWriteTimeout = HttpResponseText.TimeoutMilliseconds(config.BrevoTimeoutSeconds, 15);

            using (Stream requestStream = request.GetRequestStream())
            {
                requestStream.Write(body, 0, body.Length);
            }

            try
            {
                using (HttpWebResponse response = (HttpWebResponse)request.GetResponse())
                {
                    return new BrevoSendResult((int)response.StatusCode, HttpResponseText.Read(response));
                }
            }
            catch (WebException ex)
            {
                HttpWebResponse response = ex.Response as HttpWebResponse;
                if (response == null) throw;

                string responseBody = HttpResponseText.Read(response);
                throw new InvalidOperationException("Brevo API returned HTTP " + ((int)response.StatusCode).ToString(CultureInfo.InvariantCulture) + ": " + responseBody);
            }
        }

        private string GetApiKey()
        {
            return secretProvider.GetSecret(config.BrevoApiKeyEnvironmentVariable);
        }

        private static string BuildPayload(BrevoEmailMessage message)
        {
            return "{" +
                "\"sender\":{\"name\":\"" + JsonFields.Escape(message.SenderName) + "\",\"email\":\"" + JsonFields.Escape(message.SenderEmail) + "\"}," +
                "\"to\":[{\"email\":\"" + JsonFields.Escape(message.RecipientEmail) + "\",\"name\":\"" + JsonFields.Escape(message.RecipientName) + "\"}]," +
                "\"subject\":\"" + JsonFields.Escape(message.Subject) + "\"," +
                "\"htmlContent\":\"" + JsonFields.Escape(message.HtmlContent) + "\"," +
                "\"tags\":[\"arcane-edr\",\"security-alert\"]" +
                "}";
        }

    }

    internal sealed class BrevoEmailMessage
    {
        public string SenderEmail;
        public string SenderName;
        public string RecipientEmail;
        public string RecipientName;
        public string Subject;
        public string HtmlContent;
    }

    internal sealed class BrevoSendResult
    {
        public BrevoSendResult(int statusCode, string responseBody)
        {
            StatusCode = statusCode;
            ResponseBody = responseBody;
        }

        public int StatusCode { get; private set; }
        public string ResponseBody { get; private set; }
    }
}
