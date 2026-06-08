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
            using (Stream stream = request.GetRequestStream())
            {
                stream.Write(body, 0, body.Length);
            }

            string responseBody;
            try
            {
                using (HttpWebResponse response = (HttpWebResponse)request.GetResponse())
                {
                    responseBody = ReadResponse(response);
                }
            }
            catch (WebException ex)
            {
                HttpWebResponse response = ex.Response as HttpWebResponse;
                if (response == null) throw;
                throw new InvalidOperationException(ProviderName + " API returned HTTP " + ((int)response.StatusCode).ToString(CultureInfo.InvariantCulture) + ": " + ReadResponse(response));
            }

            string text = ExtractOutputText(responseBody);
            AiAnalysisResult result = ParseAnalysisJson(text);
            result.ProviderName = ProviderName;
            result.RawText = text;
            result.ProviderOutcomes.Add(ToOutcome(result, "completed", ""));
            WriteAnalysisRecord(result, analysisType);
            return result;
        }

        private string BuildRequestJson(string prompt, int maxTokens)
        {
            return "{" +
                "\"model\":\"" + JsonEscape(settings.Model) + "\"," +
                "\"max_tokens\":" + maxTokens.ToString(CultureInfo.InvariantCulture) + "," +
                "\"messages\":[{\"role\":\"user\",\"content\":\"" + JsonEscape(prompt) + "\"}]" +
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

        private static AiAnalysisResult ParseAnalysisJson(string text)
        {
            AiAnalysisResult result = new AiAnalysisResult();
            result.RawText = text;

            try
            {
                string json = ExtractJsonObject(text);
                JavaScriptSerializer serializer = new JavaScriptSerializer();
                IDictionary parsed = serializer.DeserializeObject(json) as IDictionary;
                if (parsed == null) return result;

                result.Alertable = ReadBool(parsed, "alertable");
                result.Score = ReadInt(parsed, "score");
                result.Title = ReadString(parsed, "title");
                result.Summary = ReadString(parsed, "summary");
                result.RecommendedAction = ReadString(parsed, "recommended_action");
            }
            catch
            {
                result.Alertable = false;
                result.Score = 0;
                result.Title = "AI analysis parse failure";
                result.Summary = text;
                result.RecommendedAction = "Review the AI analysis output.";
            }

            return result;
        }

        private void WriteAnalysisRecord(AiAnalysisResult result, string analysisType)
        {
            try
            {
                string path = Path.Combine(config.LogDirectory, "ArcaneAIAnalysis.jsonl");
                string line = "{" +
                    "\"timestamp_utc\":\"" + DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ", CultureInfo.InvariantCulture) + "\"," +
                    "\"provider\":\"" + JsonEscape(ProviderName) + "\"," +
                    "\"analysis_type\":\"" + JsonEscape(analysisType) + "\"," +
                    "\"alertable\":" + (result.Alertable ? "true" : "false") + "," +
                    "\"score\":" + result.Score.ToString(CultureInfo.InvariantCulture) + "," +
                    "\"title\":\"" + JsonEscape(result.Title) + "\"," +
                    "\"summary\":\"" + JsonEscape(result.Summary) + "\"," +
                    "\"recommended_action\":\"" + JsonEscape(result.RecommendedAction) + "\"" +
                    "}";
                lock (AiAnalysisRecordWriteLock.Sync)
                {
                    File.AppendAllText(path, line + Environment.NewLine);
                }
            }
            catch (Exception ex)
            {
                logger.Warn("AI analysis record write failed: " + ex.Message);
            }
        }

        private AiProviderAnalysisOutcome ToOutcome(AiAnalysisResult result, string status, string error)
        {
            AiProviderAnalysisOutcome outcome = new AiProviderAnalysisOutcome();
            outcome.ProviderName = ProviderName;
            outcome.Status = status;
            outcome.Alertable = result.Alertable;
            outcome.Score = result.Score;
            outcome.Title = result.Title;
            outcome.Summary = result.Summary;
            outcome.RecommendedAction = result.RecommendedAction;
            outcome.Error = error;
            return outcome;
        }

        private static string ReadResponse(HttpWebResponse response)
        {
            using (Stream responseStream = response.GetResponseStream())
            {
                if (responseStream == null) return "";
                using (StreamReader reader = new StreamReader(responseStream))
                {
                    return reader.ReadToEnd();
                }
            }
        }

        private static string ExtractJsonObject(string text)
        {
            int start = text.IndexOf('{');
            int end = text.LastIndexOf('}');
            if (start >= 0 && end > start) return text.Substring(start, end - start + 1);
            return text;
        }

        private static bool ReadBool(IDictionary parsed, string key)
        {
            if (!parsed.Contains(key) || parsed[key] == null) return false;
            object value = parsed[key];
            if (value is bool) return (bool)value;
            return value.ToString().Equals("true", StringComparison.OrdinalIgnoreCase);
        }

        private static int ReadInt(IDictionary parsed, string key)
        {
            if (!parsed.Contains(key) || parsed[key] == null) return 0;
            int value;
            return Int32.TryParse(parsed[key].ToString(), out value) ? value : 0;
        }

        private static string ReadString(IDictionary parsed, string key)
        {
            if (!parsed.Contains(key) || parsed[key] == null) return "";
            return parsed[key].ToString();
        }

        private static string JsonEscape(string value)
        {
            if (value == null) return "";
            return value
                .Replace("\\", "\\\\")
                .Replace("\"", "\\\"")
                .Replace("\r", "\\r")
                .Replace("\n", "\\n")
                .Replace("\t", "\\t");
        }
    }
}
