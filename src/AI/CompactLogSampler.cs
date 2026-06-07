using System;
using System.Collections;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Text;
using System.Text.RegularExpressions;
using System.Web.Script.Serialization;

namespace ArcaneEDR
{
    internal sealed class CompactLogSampler
    {
        private readonly MonitorConfig config;

        public CompactLogSampler(MonitorConfig config)
        {
            this.config = config;
        }

        public string BuildPayload(HealthState state)
        {
            int includedAlertMinimumScore = IncludedAlertMinimumScore();
            StringBuilder builder = new StringBuilder();
            builder.AppendLine("arcane_edr_compact_log_sample");
            builder.AppendLine("utc=" + DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ", CultureInfo.InvariantCulture));
            builder.AppendLine("baseline_learning_mode=" + config.BaselineLearningMode);
            builder.AppendLine("included_alert_minimum_score=" + includedAlertMinimumScore.ToString(CultureInfo.InvariantCulture));
            builder.AppendLine("response_mode=" + config.ResponseMode);
            builder.AppendLine("external_alert_provider=" + config.ExternalAlertProvider);
            builder.AppendLine("privacy_mode=redacted_summary_only");
            builder.AppendLine("omitted_fields=alert_body,entity,command_line,script_block,user,path,ip,url,email,secrets");
            builder.AppendLine("poll_count=" + state.PollCount.ToString(CultureInfo.InvariantCulture));
            builder.AppendLine("alert_count=" + state.AlertCount.ToString(CultureInfo.InvariantCulture));
            builder.AppendLine("poll_failures=" + state.PollFailures.ToString(CultureInfo.InvariantCulture));
            builder.AppendLine("last_start_utc=" + Format(state.LastStartUtc));
            builder.AppendLine("last_clean_stop_utc=" + Format(state.LastCleanStopUtc));
            builder.AppendLine("last_heartbeat_utc=" + Format(state.LastHeartbeatUtc));
            builder.AppendLine();
            builder.AppendLine("[recent_arcane_edr_summary]");
            builder.AppendLine(ReadTail(Path.Combine(config.LogDirectory, "ArcaneEDR.log"), config.OpenAIAnalysisMaxLogLines, delegate(string line)
            {
                return SummarizeMonitorLine(line, includedAlertMinimumScore, config.OpenAIAnalysisExcludedRuleIds);
            }));
            builder.AppendLine();
            builder.AppendLine("[recent_arcane_edr_alert_summaries]");
            builder.AppendLine(ReadTail(Path.Combine(config.LogDirectory, "ArcaneAlerts.jsonl"), config.OpenAIAnalysisMaxAlertLines, delegate(string line)
            {
                return SummarizeAlertJsonLine(line, includedAlertMinimumScore, config.OpenAIAnalysisExcludedRuleIds);
            }));

            string payload = builder.ToString();
            if (payload.Length <= config.OpenAIAnalysisMaxChars) return payload;
            return payload.Substring(payload.Length - config.OpenAIAnalysisMaxChars);
        }

        private static string ReadTail(string path, int maxLines, Func<string, string> summarize)
        {
            if (!File.Exists(path)) return "";

            Queue<string> lines = new Queue<string>();
            foreach (string line in File.ReadLines(path))
            {
                lines.Enqueue(line);
                while (lines.Count > maxLines)
                {
                    lines.Dequeue();
                }
            }

            StringBuilder builder = new StringBuilder();
            foreach (string line in lines)
            {
                string summary = summarize(line);
                if (!String.IsNullOrWhiteSpace(summary))
                {
                    builder.AppendLine(summary);
                }
            }

            return builder.ToString();
        }

        private int IncludedAlertMinimumScore()
        {
            return config.BaselineLearningMode
                ? config.OpenAIAnalysisBaselineMinimumIncludedAlertScore
                : config.OpenAIAnalysisMinimumIncludedAlertScore;
        }

        private static string SummarizeMonitorLine(string line, int includedAlertMinimumScore, HashSet<string> excludedRuleIds)
        {
            if (String.IsNullOrWhiteSpace(line)) return "";

            string timestamp = line.Length >= 20 ? line.Substring(0, 20).Trim() : "";
            string remainder = line.Length > 20 ? line.Substring(20).Trim() : line.Trim();
            string level = FirstToken(remainder);
            string message = remainder.Length > level.Length ? remainder.Substring(level.Length).Trim() : "";

            if (level.Equals("ALERT", StringComparison.OrdinalIgnoreCase))
            {
                int score = ExtractBracketScore(message);
                if (score >= 0 && score < includedAlertMinimumScore)
                {
                    return "";
                }

                int details = message.IndexOf(" | ", StringComparison.Ordinal);
                string header = details >= 0 ? message.Substring(0, details) : message;
                string ruleId = ExtractAlertRuleId(header);
                if (excludedRuleIds.Contains(ruleId))
                {
                    return "";
                }

                return SanitizeText(timestamp + " ALERT " + header);
            }

            if (level.Equals("INFO", StringComparison.OrdinalIgnoreCase) &&
                message.StartsWith("OpenAI analysis completed", StringComparison.OrdinalIgnoreCase))
            {
                return "";
            }

            if (level.Equals("WARN", StringComparison.OrdinalIgnoreCase) ||
                level.Equals("ERROR", StringComparison.OrdinalIgnoreCase))
            {
                string category = message;
                int colon = category.IndexOf(':');
                if (colon >= 0) category = category.Substring(0, colon);
                return SanitizeText(timestamp + " " + level.ToUpperInvariant() + " " + category);
            }

            if (level.Equals("INFO", StringComparison.OrdinalIgnoreCase))
            {
                if (message.StartsWith("Monitor started", StringComparison.OrdinalIgnoreCase) ||
                    message.StartsWith("Monitor stopped", StringComparison.OrdinalIgnoreCase) ||
                    message.StartsWith("Loaded ", StringComparison.OrdinalIgnoreCase))
                {
                    return SanitizeText(timestamp + " INFO " + message);
                }
            }

            return "";
        }

        private static string SummarizeAlertJsonLine(string line, int includedAlertMinimumScore, HashSet<string> excludedRuleIds)
        {
            if (String.IsNullOrWhiteSpace(line)) return "";

            try
            {
                JavaScriptSerializer serializer = new JavaScriptSerializer();
                IDictionary parsed = serializer.DeserializeObject(line) as IDictionary;
                if (parsed == null) return "alert_record_unparseable";

                int score = ReadInt(parsed, "score");
                if (score < includedAlertMinimumScore)
                {
                    return "";
                }

                string ruleId = Read(parsed, "rule_id");
                if (excludedRuleIds.Contains(ruleId))
                {
                    return "";
                }

                return "timestamp_utc=" + Read(parsed, "timestamp_utc") +
                    " rule_id=" + SanitizeToken(ruleId) +
                    " category=" + SanitizeToken(Read(parsed, "category")) +
                    " maintenance_context=" + SanitizeToken(Read(parsed, "maintenance_context")) +
                    " severity=" + SanitizeToken(Read(parsed, "severity")) +
                    " score=" + score.ToString(CultureInfo.InvariantCulture) +
                    " title=" + SanitizeText(Read(parsed, "title"));
            }
            catch
            {
                return "alert_record_unparseable";
            }
        }

        private static string ExtractOpenAiOutcome(string message)
        {
            string alertable = ExtractAssignment(message, "alertable");
            string score = ExtractAssignment(message, "score");
            return "alertable=" + SanitizeToken(alertable) + " score=" + SanitizeToken(score);
        }

        private static string ExtractAssignment(string text, string key)
        {
            Match match = Regex.Match(text, "(?:^|\\s)" + Regex.Escape(key) + "=([^\\s]+)", RegexOptions.IgnoreCase);
            return match.Success ? match.Groups[1].Value : "";
        }

        private static string Read(IDictionary parsed, string key)
        {
            if (!parsed.Contains(key) || parsed[key] == null) return "";
            return parsed[key].ToString();
        }

        private static int ReadInt(IDictionary parsed, string key)
        {
            if (!parsed.Contains(key) || parsed[key] == null) return 0;
            int value;
            return Int32.TryParse(parsed[key].ToString(), out value) ? value : 0;
        }

        private static int ExtractBracketScore(string text)
        {
            Match match = Regex.Match(text ?? "", "\\[(\\d{1,3})\\]");
            if (!match.Success) return -1;

            int score;
            return Int32.TryParse(match.Groups[1].Value, out score) ? score : -1;
        }

        private static string ExtractAlertRuleId(string header)
        {
            if (String.IsNullOrWhiteSpace(header)) return "";
            Match match = Regex.Match(header, "^\\s*\\[\\d{1,3}\\]\\s+([^\\s]+)");
            return match.Success ? match.Groups[1].Value : "";
        }

        private static string FirstToken(string value)
        {
            if (String.IsNullOrWhiteSpace(value)) return "";
            int space = value.IndexOf(' ');
            return space >= 0 ? value.Substring(0, space) : value;
        }

        private static string SanitizeToken(string value)
        {
            if (String.IsNullOrWhiteSpace(value)) return "";
            return SanitizeText(value).Replace(" ", "_");
        }

        private static string SanitizeText(string value)
        {
            if (String.IsNullOrWhiteSpace(value)) return "";

            string result = value;
            result = Regex.Replace(result, "(?i)bearer\\s+[A-Za-z0-9._\\-+/=]{8,}", "Bearer [redacted-secret]");
            result = Regex.Replace(result, "(?i)(api[_-]?key|apikey|token|secret|password|passwd|pwd|authorization|client_secret|access_token|refresh_token)\\s*[:=]\\s*[^\\s,;\\}\\]]+", "$1=[redacted-secret]");
            result = Regex.Replace(result, "[A-Za-z0-9_-]{20,}\\.[A-Za-z0-9_-]{20,}\\.[A-Za-z0-9_-]{10,}", "[redacted-jwt]");
            result = Regex.Replace(result, "[A-Za-z0-9._%+\\-]+@[A-Za-z0-9.\\-]+\\.[A-Za-z]{2,}", "[redacted-email]");
            result = Regex.Replace(result, "(?i)https?://[^\\s\"'<>]+", "[redacted-url]");
            result = Regex.Replace(result, "(?i)\\b(?:[a-z0-9](?:[a-z0-9\\-]{0,61}[a-z0-9])?\\.)+[a-z]{2,}\\b", "[redacted-domain]");
            result = Regex.Replace(result, "\\b(?:\\d{1,3}\\.){3}\\d{1,3}\\b", "[redacted-ip]");
            result = Regex.Replace(result, "(?i)\\b[0-9a-f]{64}\\b", "[redacted-sha256]");
            result = Regex.Replace(result, "(?i)C:\\\\Users\\\\[^\\\\\\s\"']+", "C:\\Users\\[redacted-user]");
            result = Regex.Replace(result, "(?i)[A-Z]:\\\\[^\\s|,\"']+", "[redacted-path]");
            result = Regex.Replace(result, "\\\\\\\\[^\\s|,\"']+", "[redacted-unc-path]");
            result = Regex.Replace(result, "(?i)(user|subject|target)=([^\\s|,]+)", "$1=[redacted-account]");
            result = Regex.Replace(result, "(?i)(command_line|parent_command_line|script_block|decodedpreview)=([^|]+)", "$1=[redacted]");
            result = Regex.Replace(result, "[A-Za-z0-9+/]{80,}={0,2}", "[redacted-encoded-data]");
            return result.Trim();
        }

        private static string Format(DateTime? value)
        {
            return value.HasValue ? value.Value.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ", CultureInfo.InvariantCulture) : "";
        }
    }
}
