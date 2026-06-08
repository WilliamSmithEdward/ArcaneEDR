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
        private readonly string providerName;

        public OpenAiCompatibleAnalysisProvider(MonitorConfig config, FileLogger logger, ISecretProvider secretProvider, string providerName)
        {
            this.config = config;
            this.logger = logger;
            this.secretProvider = secretProvider;
            this.providerName = String.IsNullOrWhiteSpace(providerName) ? "OpenAICompatible" : providerName;
        }

        public string ProviderName
        {
            get { return providerName; }
        }

        public bool IsConfigured
        {
            get
            {
                return (!RequiresApiKey() || !String.IsNullOrWhiteSpace(GetApiKey())) &&
                    !String.IsNullOrWhiteSpace(config.ActiveAiAnalysisApiUrl()) &&
                    !String.IsNullOrWhiteSpace(config.ActiveAiAnalysisModel());
            }
        }

        public string MissingConfigurationReason
        {
            get
            {
                if (String.IsNullOrWhiteSpace(config.ActiveAiAnalysisApiUrl())) return "AI analysis API URL is missing.";
                if (String.IsNullOrWhiteSpace(config.ActiveAiAnalysisModel())) return "AI analysis model is missing.";
                if (RequiresApiKey() && String.IsNullOrWhiteSpace(GetApiKey())) return "AI analysis API key environment variable is not visible: " + config.ActiveAiAnalysisApiKeyEnvironmentVariable();
                return "";
            }
        }

        public OpenAiAnalysisResult Analyze(string compactLogPayload)
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

        public OpenAiAnalysisResult AnalyzeDailyReport(string dailyReportPayload)
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

        private OpenAiAnalysisResult SendRequestAndParse(string requestJson, string analysisType)
        {
            string apiKey = GetApiKey();
            byte[] body = Encoding.UTF8.GetBytes(requestJson);
            HttpWebRequest request = (HttpWebRequest)WebRequest.Create(config.ActiveAiAnalysisApiUrl());
            request.Method = "POST";
            request.Accept = "application/json";
            request.ContentType = "application/json";
            string headerName = config.ActiveAiAnalysisAuthHeaderName();
            if (!String.IsNullOrWhiteSpace(headerName))
            {
                request.Headers[headerName] = config.ActiveAiAnalysisAuthHeaderPrefix() + apiKey;
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
                throw new InvalidOperationException(providerName + " API returned HTTP " + ((int)response.StatusCode).ToString(CultureInfo.InvariantCulture) + ": " + ReadResponse(response));
            }

            string text = ExtractOutputText(responseBody);
            OpenAiAnalysisResult result = ParseAnalysisJson(text);
            result.RawText = text;
            WriteAnalysisRecord(result, analysisType);
            return result;
        }

        private string GetApiKey()
        {
            return secretProvider.GetSecret(config.ActiveAiAnalysisApiKeyEnvironmentVariable());
        }

        private bool RequiresApiKey()
        {
            return !String.IsNullOrWhiteSpace(config.ActiveAiAnalysisAuthHeaderName());
        }

        private string BuildRequestJson(string compactLogPayload)
        {
            string prompt =
                "You are a security analyst reviewing compact Windows host monitor logs. " +
                "Decide whether this sample is alert-worthy beyond routine noise. " +
                "Return only compact JSON with keys: alertable boolean, score integer 0-100, title string, summary string, recommended_action string. " +
                "Be conservative: alertable=true only for likely compromise, RAT behavior, C2, suspicious persistence, repeated failures, or meaningful degradation. " +
                "If baseline_learning_mode=True, treat service restarts, validation, build/publish/install scripts, ACL hardening, and monitor configuration changes as likely maintenance unless high-confidence malicious indicators remain after filtering. " +
                "Keep summary under 80 words and recommended_action under 50 words.\n\n" +
                compactLogPayload;

            return "{" +
                "\"model\":\"" + JsonEscape(config.ActiveAiAnalysisModel()) + "\"," +
                "\"input\":\"" + JsonEscape(prompt) + "\"," +
                "\"max_output_tokens\":500," +
                "\"reasoning\":{\"effort\":\"low\"}," +
                "\"store\":false" +
                "}";
        }

        private string BuildDailyReportRequestJson(string dailyReportPayload)
        {
            string prompt =
                "You are a cautious security analyst writing the AI review section of a daily Arcane EDR host-security report. " +
                "The recipient's main question is: is compromise confirmed, is review recommended, or are there no immediate findings from the available evidence? " +
                "Review the redacted aggregate 24-hour report payload and make a high-level, human-readable judgment. " +
                "Do not invent source-event fields such as paths, IPs, users, domains, or command lines because the payload intentionally omits them. " +
                "Do not assume compromise from alert volume alone. Volume can reflect baseline learning, repeated low-score rules, agent activity, maintenance, or limited aggregate context. " +
                "Explicitly account for false-positive potential, baseline_learning_mode, maintenance_context, automation or agent context, collector gaps, and whether full source-event context is absent. " +
                "Use phrases like 'no confirmed compromise' or 'needs review' when evidence is suggestive but not conclusive. " +
                "Return only compact JSON with keys: alertable boolean, score integer 0-100, title string, summary string, recommended_action string. " +
                "Use alertable=true only when high-confidence signals justify priority review after considering plausible false positives; do not set alertable=true for routine baseline noise. " +
                "Keep the title plain and verdict-like. Keep summary under 120 words and recommended_action under 60 words.\n\n" +
                dailyReportPayload;

            return "{" +
                "\"model\":\"" + JsonEscape(config.ActiveAiAnalysisModel()) + "\"," +
                "\"input\":\"" + JsonEscape(prompt) + "\"," +
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

        private static OpenAiAnalysisResult ParseAnalysisJson(string text)
        {
            OpenAiAnalysisResult result = new OpenAiAnalysisResult();
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

        private void WriteAnalysisRecord(OpenAiAnalysisResult result, string analysisType)
        {
            try
            {
                string path = Path.Combine(config.LogDirectory, "ArcaneOpenAIAnalysis.jsonl");
                string line = "{" +
                    "\"timestamp_utc\":\"" + DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ", CultureInfo.InvariantCulture) + "\"," +
                    "\"analysis_type\":\"" + JsonEscape(analysisType) + "\"," +
                    "\"alertable\":" + (result.Alertable ? "true" : "false") + "," +
                    "\"score\":" + result.Score.ToString(CultureInfo.InvariantCulture) + "," +
                    "\"title\":\"" + JsonEscape(result.Title) + "\"," +
                    "\"summary\":\"" + JsonEscape(result.Summary) + "\"," +
                    "\"recommended_action\":\"" + JsonEscape(result.RecommendedAction) + "\"" +
                    "}";
                File.AppendAllText(path, line + Environment.NewLine);
            }
            catch (Exception ex)
            {
                logger.Warn("AI analysis record write failed: " + ex.Message);
            }
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
