using System;
using System.Collections;
using System.Globalization;
using System.IO;
using System.Net;
using System.Text;
using System.Web.Script.Serialization;

namespace ArcaneEDR
{
    internal sealed class AnthropicAnalysisProvider : IAiAnalysisProvider
    {
        private readonly MonitorConfig config;
        private readonly FileLogger logger;
        private readonly ISecretProvider secretProvider;
        private readonly AiAnalysisProviderSettings settings;

        public AnthropicAnalysisProvider(MonitorConfig config, FileLogger logger, ISecretProvider secretProvider, AiAnalysisProviderSettings settings)
        {
            this.config = config;
            this.logger = logger;
            this.secretProvider = secretProvider;
            this.settings = settings;
        }

        public string ProviderName
        {
            get { return settings.DisplayName; }
        }

        public bool IsConfigured
        {
            get
            {
                return !String.IsNullOrWhiteSpace(settings.ApiUrl) &&
                    !String.IsNullOrWhiteSpace(settings.Model) &&
                    (!RequiresApiKey() || !String.IsNullOrWhiteSpace(GetApiKey())) &&
                    !String.IsNullOrWhiteSpace(settings.VersionHeaderName) &&
                    !String.IsNullOrWhiteSpace(settings.VersionHeaderValue);
            }
        }

        public string MissingConfigurationReason
        {
            get
            {
                if (String.IsNullOrWhiteSpace(settings.ApiUrl)) return ProviderName + " AI analysis API URL is missing.";
                if (String.IsNullOrWhiteSpace(settings.Model)) return ProviderName + " AI analysis model is missing.";
                if (RequiresApiKey() && String.IsNullOrWhiteSpace(GetApiKey())) return ProviderName + " AI analysis API key environment variable is not visible: " + settings.ApiKeyEnvironmentVariable;
                if (String.IsNullOrWhiteSpace(settings.VersionHeaderName)) return ProviderName + " AI analysis version header name is missing.";
                if (String.IsNullOrWhiteSpace(settings.VersionHeaderValue)) return ProviderName + " AI analysis version header value is missing.";
                return "";
            }
        }

        public AiAnalysisResult Analyze(string compactLogPayload)
        {
            return SendRequestAndParse(BuildRequestJson(AiAnalysisPrompts.CompactLogPrompt(compactLogPayload), 500), "compact_log");
        }

        public AiAnalysisResult AnalyzeDailyReport(string dailyReportPayload)
        {
            return SendRequestAndParse(BuildRequestJson(AiAnalysisPrompts.DailyReportPrompt(dailyReportPayload), 700), "daily_report");
        }

        private AiAnalysisResult SendRequestAndParse(string requestJson, string analysisType)
        {
            string apiKey = GetApiKey();
            if (RequiresApiKey() && String.IsNullOrWhiteSpace(apiKey))
            {
                throw new InvalidOperationException("AI analysis API key is missing for " + ProviderName + ".");
            }

            ServicePointManager.SecurityProtocol = ServicePointManager.SecurityProtocol | (SecurityProtocolType)3072;

            byte[] body = Encoding.UTF8.GetBytes(requestJson);
            HttpWebRequest request = (HttpWebRequest)WebRequest.Create(settings.ApiUrl);
            request.Method = "POST";
            request.Accept = "application/json";
            request.ContentType = "application/json";
            request.Headers[settings.VersionHeaderName] = settings.VersionHeaderValue;
            if (!String.IsNullOrWhiteSpace(settings.AuthHeaderName))
            {
                request.Headers[settings.AuthHeaderName] = (settings.AuthHeaderPrefix ?? "") + apiKey;
            }

            request.ContentLength = body.Length;
            request.Timeout = HttpResponseText.TimeoutMilliseconds(config.AIAnalysisTimeoutSeconds, 30);
            request.ReadWriteTimeout = HttpResponseText.TimeoutMilliseconds(config.AIAnalysisTimeoutSeconds, 30);
            using (Stream stream = request.GetRequestStream())
            {
                stream.Write(body, 0, body.Length);
            }

            string responseBody;
            try
            {
                using (HttpWebResponse response = (HttpWebResponse)request.GetResponse())
                {
                    responseBody = HttpResponseText.Read(response);
                }
            }
            catch (WebException ex)
            {
                HttpWebResponse response = ex.Response as HttpWebResponse;
                if (response == null) throw;
                throw new InvalidOperationException(ProviderName + " API returned HTTP " + ((int)response.StatusCode).ToString(CultureInfo.InvariantCulture) + ": " + HttpResponseText.Read(response));
            }

            string text = ExtractOutputText(responseBody);
            AiAnalysisResult result = AiAnalysisProviderSupport.ParseAnalysisJson(text);
            result.ProviderName = ProviderName;
            result.RawText = text;
            result.ProviderOutcomes.Add(AiAnalysisProviderSupport.ToOutcome(ProviderName, result, "completed", ""));
            AiAnalysisProviderSupport.WriteAnalysisRecord(config.LogDirectory, ProviderName, result, analysisType, logger);
            return result;
        }

        private string BuildRequestJson(string prompt, int maxTokens)
        {
            return "{" +
                "\"model\":\"" + JsonFields.Escape(settings.Model) + "\"," +
                "\"max_tokens\":" + maxTokens.ToString(CultureInfo.InvariantCulture) + "," +
                "\"messages\":[{\"role\":\"user\",\"content\":\"" + JsonFields.Escape(prompt) + "\"}]" +
                "}";
        }

        private string GetApiKey()
        {
            return secretProvider.GetSecret(settings.ApiKeyEnvironmentVariable);
        }

        private bool RequiresApiKey()
        {
            return !String.IsNullOrWhiteSpace(settings.AuthHeaderName);
        }

        private static string ExtractOutputText(string responseBody)
        {
            JavaScriptSerializer serializer = new JavaScriptSerializer();
            object parsed = serializer.DeserializeObject(responseBody);
            IDictionary root = parsed as IDictionary;
            if (root == null) return responseBody;

            IList content = root["content"] as IList;
            if (content == null) return responseBody;

            StringBuilder builder = new StringBuilder();
            foreach (object item in content)
            {
                IDictionary contentItem = item as IDictionary;
                if (contentItem == null) continue;
                if (contentItem.Contains("text") && contentItem["text"] != null)
                {
                    builder.Append(contentItem["text"].ToString());
                }
            }

            return builder.ToString();
        }

    }
}
