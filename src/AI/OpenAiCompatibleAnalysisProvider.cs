using System;
using System.Collections;
using System.Globalization;
using System.IO;
using System.Net;
using System.Text;
using System.Web.Script.Serialization;

namespace ArcaneEDR
{
    internal sealed class OpenAiCompatibleAnalysisProvider : IAiAnalysisProvider
    {
        private readonly MonitorConfig config;
        private readonly FileLogger logger;
        private readonly ISecretProvider secretProvider;
        private readonly AiAnalysisProviderSettings settings;

        public OpenAiCompatibleAnalysisProvider(MonitorConfig config, FileLogger logger, ISecretProvider secretProvider, AiAnalysisProviderSettings settings)
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
                return (!RequiresApiKey() || !String.IsNullOrWhiteSpace(GetApiKey())) &&
                    !String.IsNullOrWhiteSpace(settings.ApiUrl) &&
                    !String.IsNullOrWhiteSpace(settings.Model);
            }
        }

        public string MissingConfigurationReason
        {
            get
            {
                if (String.IsNullOrWhiteSpace(settings.ApiUrl)) return ProviderName + " AI analysis API URL is missing.";
                if (String.IsNullOrWhiteSpace(settings.Model)) return ProviderName + " AI analysis model is missing.";
                if (RequiresApiKey() && String.IsNullOrWhiteSpace(GetApiKey())) return ProviderName + " AI analysis API key environment variable is not visible: " + settings.ApiKeyEnvironmentVariable;
                return "";
            }
        }

        public AiAnalysisResult Analyze(string compactLogPayload)
        {
            string apiKey = GetApiKey();
            if (RequiresApiKey() && String.IsNullOrWhiteSpace(apiKey))
            {
                throw new InvalidOperationException("AI analysis API key is missing.");
            }

            ServicePointManager.SecurityProtocol = ServicePointManager.SecurityProtocol | (SecurityProtocolType)3072;

            string requestJson = BuildRequestJson(compactLogPayload);
            return SendRequestAndParse(requestJson, "compact_log");
        }

        public AiAnalysisResult AnalyzeDailyReport(string dailyReportPayload)
        {
            string apiKey = GetApiKey();
            if (RequiresApiKey() && String.IsNullOrWhiteSpace(apiKey))
            {
                throw new InvalidOperationException("AI analysis API key is missing.");
            }

            ServicePointManager.SecurityProtocol = ServicePointManager.SecurityProtocol | (SecurityProtocolType)3072;

            string requestJson = BuildDailyReportRequestJson(dailyReportPayload);
            return SendRequestAndParse(requestJson, "daily_report");
        }

        private AiAnalysisResult SendRequestAndParse(string requestJson, string analysisType)
        {
            string apiKey = GetApiKey();
            byte[] body = Encoding.UTF8.GetBytes(requestJson);
            HttpWebRequest request = (HttpWebRequest)WebRequest.Create(settings.ApiUrl);
            request.Method = "POST";
            request.Accept = "application/json";
            request.ContentType = "application/json";
            string headerName = settings.AuthHeaderName;
            if (!String.IsNullOrWhiteSpace(headerName))
            {
                request.Headers[headerName] = (settings.AuthHeaderPrefix ?? "") + apiKey;
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

        private string GetApiKey()
        {
            return secretProvider.GetSecret(settings.ApiKeyEnvironmentVariable);
        }

        private bool RequiresApiKey()
        {
            return !String.IsNullOrWhiteSpace(settings.AuthHeaderName);
        }

        private string BuildRequestJson(string compactLogPayload)
        {
            string prompt = AiAnalysisPrompts.CompactLogPrompt(compactLogPayload);

            return "{" +
                "\"model\":\"" + JsonFields.Escape(settings.Model) + "\"," +
                "\"input\":\"" + JsonFields.Escape(prompt) + "\"," +
                "\"max_output_tokens\":500," +
                "\"reasoning\":{\"effort\":\"low\"}," +
                "\"store\":false" +
                "}";
        }

        private string BuildDailyReportRequestJson(string dailyReportPayload)
        {
            string prompt = AiAnalysisPrompts.DailyReportPrompt(dailyReportPayload);

            return "{" +
                "\"model\":\"" + JsonFields.Escape(settings.Model) + "\"," +
                "\"input\":\"" + JsonFields.Escape(prompt) + "\"," +
                "\"max_output_tokens\":700," +
                "\"reasoning\":{\"effort\":\"low\"}," +
                "\"store\":false" +
                "}";
        }

        private static string ExtractOutputText(string responseBody)
        {
            JavaScriptSerializer serializer = new JavaScriptSerializer();
            object parsed = serializer.DeserializeObject(responseBody);
            IDictionary root = parsed as IDictionary;
            if (root == null) return responseBody;

            if (root.Contains("output_text")) return root["output_text"] == null ? "" : root["output_text"].ToString();

            IList output = root["output"] as IList;
            if (output == null) return responseBody;

            StringBuilder builder = new StringBuilder();
            foreach (object item in output)
            {
                IDictionary outputItem = item as IDictionary;
                if (outputItem == null) continue;
                IList content = outputItem["content"] as IList;
                if (content == null) continue;

                foreach (object contentItem in content)
                {
                    IDictionary contentMap = contentItem as IDictionary;
                    if (contentMap != null && contentMap.Contains("text") && contentMap["text"] != null)
                    {
                        builder.Append(contentMap["text"].ToString());
                    }
                }
            }

            return builder.ToString();
        }

    }
}
