using System;
using System.Collections;
using System.Globalization;
using System.IO;
using System.Web.Script.Serialization;

namespace ArcaneEDR
{
    internal static class AiAnalysisProviderSupport
    {
        public static AiAnalysisResult ParseAnalysisJson(string text)
        {
            AiAnalysisResult result = new AiAnalysisResult();
            result.RawText = text;

            try
            {
                string json = JsonFields.ExtractObject(text);
                JavaScriptSerializer serializer = new JavaScriptSerializer();
                IDictionary parsed = serializer.DeserializeObject(json) as IDictionary;
                if (parsed == null) return result;

                result.Alertable = JsonFields.ReadBool(parsed, "alertable");
                result.Score = JsonFields.ReadInt(parsed, "score");
                result.Title = JsonFields.ReadString(parsed, "title");
                result.Summary = JsonFields.ReadString(parsed, "summary");
                result.RecommendedAction = JsonFields.ReadString(parsed, "recommended_action");
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

        public static AiProviderAnalysisOutcome ToOutcome(string providerName, AiAnalysisResult result, string status, string error)
        {
            AiProviderAnalysisOutcome outcome = new AiProviderAnalysisOutcome();
            outcome.ProviderName = providerName;
            outcome.Status = status;
            outcome.Alertable = result.Alertable;
            outcome.Score = result.Score;
            outcome.Title = result.Title;
            outcome.Summary = result.Summary;
            outcome.RecommendedAction = result.RecommendedAction;
            outcome.Error = error;
            return outcome;
        }

        public static void WriteAnalysisRecord(string logDirectory, string providerName, AiAnalysisResult result, string analysisType, FileLogger logger)
        {
            try
            {
                string path = Path.Combine(logDirectory, "ArcaneAIAnalysis.jsonl");
                string line = "{" +
                    "\"timestamp_utc\":\"" + UtcTimestamp.Format(DateTime.UtcNow) + "\"," +
                    "\"provider\":\"" + JsonFields.Escape(providerName) + "\"," +
                    "\"analysis_type\":\"" + JsonFields.Escape(analysisType) + "\"," +
                    "\"alertable\":" + (result.Alertable ? "true" : "false") + "," +
                    "\"score\":" + result.Score.ToString(CultureInfo.InvariantCulture) + "," +
                    "\"title\":\"" + JsonFields.Escape(result.Title) + "\"," +
                    "\"summary\":\"" + JsonFields.Escape(result.Summary) + "\"," +
                    "\"recommended_action\":\"" + JsonFields.Escape(result.RecommendedAction) + "\"" +
                    "}";
                lock (AiAnalysisRecordWriteLock.Sync)
                {
                    File.AppendAllText(path, line + Environment.NewLine);
                }
            }
            catch (Exception ex)
            {
                if (logger != null) logger.Warn("AI analysis record write failed: " + ex.Message);
            }
        }
    }
}
