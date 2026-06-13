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
            string logPath = Path.Combine(config.LogDirectory, "ArcaneEDR.log");
            string alertsPath = Path.Combine(config.LogDirectory, "ArcaneAlerts.jsonl");
            StringBuilder builder = new StringBuilder();
            builder.AppendLine("arcane_edr_compact_log_sample");
            builder.AppendLine("utc=" + UtcTimestamp.Format(DateTime.UtcNow));
            builder.AppendLine("baseline_learning_mode=" + config.BaselineLearningMode);
            builder.AppendLine("included_alert_minimum_score=" + includedAlertMinimumScore.ToString(CultureInfo.InvariantCulture));
            builder.AppendLine("aggregate_alert_window_lines=" + config.AIAnalysisMaxAlertLines.ToString(CultureInfo.InvariantCulture));
            builder.AppendLine("aggregate_significant_minimum_score=60");
            builder.AppendLine("response_mode=" + config.ResponseMode);
            builder.AppendLine("external_alert_provider=" + config.ExternalAlertProvider);
            builder.AppendLine("privacy_mode=redacted_summary_only");
            builder.AppendLine("omitted_fields=raw_alert_body,raw_entity,command_line,script_block,user,path,ip,url,email,secrets");
            builder.AppendLine("included_remote_context=redacted_owner_asn_domain_country_policy_process_port");
            builder.AppendLine("poll_count=" + state.PollCount.ToString(CultureInfo.InvariantCulture));
            builder.AppendLine("alert_count=" + state.AlertCount.ToString(CultureInfo.InvariantCulture));
            builder.AppendLine("poll_failures=" + state.PollFailures.ToString(CultureInfo.InvariantCulture));
            builder.AppendLine("last_start_utc=" + UtcTimestamp.Format(state.LastStartUtc));
            builder.AppendLine("last_clean_stop_utc=" + UtcTimestamp.Format(state.LastCleanStopUtc));
            builder.AppendLine("last_heartbeat_utc=" + UtcTimestamp.Format(state.LastHeartbeatUtc));
            builder.AppendLine();
            builder.AppendLine("[recent_arcane_edr_summary]");
            builder.AppendLine(ReadTail(logPath, config.AIAnalysisMaxLogLines, delegate(string line)
            {
                return SummarizeMonitorLine(line, includedAlertMinimumScore, config.AIAnalysisExcludedRuleIds);
            }));
            builder.AppendLine();
            builder.AppendLine("[recent_arcane_edr_alert_summaries]");
            builder.AppendLine(ReadTail(alertsPath, config.AIAnalysisMaxAlertLines, delegate(string line)
            {
                return SummarizeAlertJsonLine(line, includedAlertMinimumScore, config.AIAnalysisExcludedRuleIds);
            }));
            builder.AppendLine();
            builder.AppendLine("[recent_arcane_edr_alert_aggregate]");
            builder.AppendLine(BuildAlertAggregate(alertsPath, config.AIAnalysisMaxAlertLines, config.AIAnalysisExcludedRuleIds));

            string payload = builder.ToString();
            if (payload.Length <= config.AIAnalysisMaxChars) return payload;
            return payload.Substring(payload.Length - config.AIAnalysisMaxChars);
        }

        private static string ReadTail(string path, int maxLines, Func<string, string> summarize)
        {
            StringBuilder builder = new StringBuilder();
            foreach (string line in TailLines(path, maxLines))
            {
                string summary = summarize(line);
                if (!String.IsNullOrWhiteSpace(summary))
                {
                    builder.AppendLine(summary);
                }
            }

            return builder.ToString();
        }

        private static List<string> TailLines(string path, int maxLines)
        {
            List<string> result = new List<string>();
            if (!File.Exists(path) || maxLines <= 0) return result;

            Queue<string> lines = new Queue<string>();
            foreach (string line in File.ReadLines(path))
            {
                lines.Enqueue(line);
                while (lines.Count > maxLines)
                {
                    lines.Dequeue();
                }
            }

            foreach (string line in lines)
            {
                result.Add(line);
            }

            return result;
        }

        private int IncludedAlertMinimumScore()
        {
            return config.BaselineLearningMode
                ? config.AIAnalysisBaselineMinimumIncludedAlertScore
                : config.AIAnalysisMinimumIncludedAlertScore;
        }

        private static string BuildAlertAggregate(string path, int maxLines, HashSet<string> excludedRuleIds)
        {
            List<string> lines = TailLines(path, maxLines);
            if (lines.Count == 0) return "window_records=0";

            AlertAggregate aggregate = new AlertAggregate();
            JavaScriptSerializer serializer = new JavaScriptSerializer();
            foreach (string line in lines)
            {
                CompactAlertRecord record = ParseAlertRecord(serializer, line);
                if (record == null)
                {
                    aggregate.ParseFailures++;
                    continue;
                }

                if (excludedRuleIds.Contains(record.RuleId))
                {
                    aggregate.ExcludedRuleRecords++;
                    continue;
                }

                aggregate.Add(record);
            }

            return aggregate.ToSummary();
        }

        private static CompactAlertRecord ParseAlertRecord(JavaScriptSerializer serializer, string line)
        {
            if (String.IsNullOrWhiteSpace(line)) return null;

            try
            {
                IDictionary parsed = serializer.DeserializeObject(line) as IDictionary;
                if (parsed == null) return null;

                CompactAlertRecord record = new CompactAlertRecord();
                record.RuleId = TextFormatting.UnknownIfBlank(JsonFields.ReadString(parsed, "rule_id"));
                record.Category = TextFormatting.UnknownIfBlank(JsonFields.ReadString(parsed, "category"));
                if (record.Category.Equals("unknown", StringComparison.OrdinalIgnoreCase))
                {
                    record.Category = AlertRuleCatalog.CategoryFor(record.RuleId);
                }

                record.Severity = TextFormatting.UnknownIfBlank(JsonFields.ReadString(parsed, "severity"));
                record.Score = JsonFields.ReadInt(parsed, "score");
                if (record.Severity.Equals("unknown", StringComparison.OrdinalIgnoreCase))
                {
                    record.Severity = AlertSeverity.FromScore(record.Score);
                }

                record.MaintenanceContext = JsonFields.ReadBool(parsed, "maintenance_context");
                record.Title = TextFormatting.UnknownIfBlank(JsonFields.ReadString(parsed, "title"));
                UtcTimestamp.TryParse(JsonFields.ReadString(parsed, "timestamp_utc"), out record.TimestampUtc);
                record.AgentContext = HasAgentContext(parsed);
                record.Why = ReadWhy(parsed);
                record.RemoteContext = ExtractRemoteContext(parsed);
                return record;
            }
            catch
            {
                return null;
            }
        }

        private static bool HasAgentContext(IDictionary parsed)
        {
            if (ContainsIgnoreCase(JsonFields.ReadString(parsed, "body"), "AgentContext: involved")) return true;
            if (ContainsIgnoreCase(JsonFields.ReadString(parsed, "entity"), "agent_context=involved")) return true;

            IList why = parsed["why"] as IList;
            if (why == null) return false;

            foreach (object item in why)
            {
                string value = item == null ? "" : item.ToString();
                if (ContainsIgnoreCase(value, "unattended-agent") ||
                    ContainsIgnoreCase(value, "agent-"))
                {
                    return true;
                }
            }

            return false;
        }

        private static string ExtractRemoteContext(IDictionary parsed)
        {
            if (parsed == null) return "";

            string text = JsonFields.ReadString(parsed, "entity") + " " +
                JsonFields.ReadString(parsed, "body") + " " +
                JsonFields.ReadString(parsed, "policy_context");
            if (String.IsNullOrWhiteSpace(text)) return "";

            List<string> parts = new List<string>();
            AddContextPart(parts, "process", ExtractTokenValue(text, "process"));
            AddContextPart(parts, "port", ExtractRemotePort(text));
            AddContextPart(parts, "owner", ExtractTokenValue(text, "owner"));
            AddContextPart(parts, "asn", ExtractTokenValue(text, "asn"));
            AddContextPart(parts, "asn_org", ExtractTokenValue(text, "asn_org"));
            AddContextPart(parts, "country", ExtractTokenValue(text, "country"));
            AddContextPart(parts, "country_lookup", ExtractTokenValue(text, "country_lookup"));
            AddContextPart(parts, "resolved_domain", ExtractTokenValue(text, "resolved_domain"));
            AddContextPart(parts, "registrable_domain", ExtractTokenValue(text, "registrable_domain"));
            AddContextPart(parts, "remote_policy", ExtractRemotePolicy(text));
            AddContextPart(parts, "policy_context", ExtractTokenValue(text, "policy"));

            return parts.Count == 0 ? "" : String.Join(" ", parts.ToArray());
        }

        private static void AddContextPart(List<string> parts, string key, string value)
        {
            if (parts == null || String.IsNullOrWhiteSpace(key) || String.IsNullOrWhiteSpace(value)) return;

            string sanitized = SanitizeContextValue(key, value);
            if (String.IsNullOrWhiteSpace(sanitized)) return;

            string item = key + "=" + sanitized;
            foreach (string existing in parts)
            {
                if (existing.Equals(item, StringComparison.OrdinalIgnoreCase)) return;
            }

            parts.Add(item);
        }

        private static string ExtractTokenValue(string text, string key)
        {
            if (String.IsNullOrWhiteSpace(text) || String.IsNullOrWhiteSpace(key)) return "";

            Match match = Regex.Match(
                text,
                "(?:^|[\\s;|])" + Regex.Escape(key) + "=([^\\s|;]+)",
                RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
            return match.Success ? match.Groups[1].Value : "";
        }

        private static string ExtractRemotePort(string text)
        {
            if (String.IsNullOrWhiteSpace(text)) return "";

            Match match = Regex.Match(
                text,
                @"Endpoint:\s+\S+\s+\S+:\d+\s+->\s+\S+:(\d{1,5})\b",
                RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
            return match.Success ? match.Groups[1].Value : "";
        }

        private static string ExtractRemotePolicy(string text)
        {
            if (String.IsNullOrWhiteSpace(text)) return "";

            Match match = Regex.Match(
                text,
                @"remote_endpoint_policy=([A-Za-z0-9_.:-]+)",
                RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
            if (match.Success) return match.Groups[1].Value;

            string id = ExtractTokenValue(text, "id");
            string action = ExtractTokenValue(text, "action");
            if (!String.IsNullOrWhiteSpace(id) && !String.IsNullOrWhiteSpace(action)) return id + ":" + action;
            return "";
        }

        private static string SanitizeContextValue(string key, string value)
        {
            if (String.IsNullOrWhiteSpace(value)) return "";

            string result = value.Trim().Trim(',', '.', ';', '|', '"', '\'');
            if (key.Equals("resolved_domain", StringComparison.OrdinalIgnoreCase) ||
                key.Equals("registrable_domain", StringComparison.OrdinalIgnoreCase))
            {
                result = String.IsNullOrWhiteSpace(result) ? "" : "present";
            }
            else
            {
                result = SanitizeContextNonDomainValue(result);
            }

            result = Regex.Replace(result, "\\s+", "_");
            result = Regex.Replace(result, "[^A-Za-z0-9_.:/=-]", "_");
            return TrimForSummary(result.Trim('_'), 120);
        }

        private static string SanitizeContextNonDomainValue(string value)
        {
            return SensitiveTextRedactor.RedactForAiPayload(value, false, false);
        }

        private static List<string> ReadWhy(IDictionary parsed)
        {
            List<string> result = new List<string>();
            IList why = parsed["why"] as IList;
            if (why == null) return result;

            foreach (object item in why)
            {
                string value = item == null ? "" : NormalizeReasonForAggregate(item.ToString());
                if (!String.IsNullOrWhiteSpace(value))
                {
                    result.Add(TrimForSummary(value, 140));
                }
            }

            return result;
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
                message.StartsWith("AI analysis completed", StringComparison.OrdinalIgnoreCase))
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

                int score = JsonFields.ReadInt(parsed, "score");
                if (score < includedAlertMinimumScore)
                {
                    return "";
                }

                string ruleId = JsonFields.ReadString(parsed, "rule_id");
                if (excludedRuleIds.Contains(ruleId))
                {
                    return "";
                }

                string remoteContext = ExtractRemoteContext(parsed);
                return "timestamp_utc=" + JsonFields.ReadString(parsed, "timestamp_utc") +
                    " system_local_time=" + SanitizeToken(JsonFields.ReadString(parsed, "system_local_time")) +
                    " rule_id=" + SanitizeToken(ruleId) +
                    " category=" + SanitizeToken(JsonFields.ReadString(parsed, "category")) +
                    " maintenance_context=" + SanitizeToken(JsonFields.ReadString(parsed, "maintenance_context")) +
                    " severity=" + SanitizeToken(JsonFields.ReadString(parsed, "severity")) +
                    " score=" + score.ToString(CultureInfo.InvariantCulture) +
                    (String.IsNullOrWhiteSpace(remoteContext) ? "" : " remote_context=\"" + remoteContext + "\"") +
                    " title=" + SanitizeText(JsonFields.ReadString(parsed, "title"));
            }
            catch
            {
                return "alert_record_unparseable";
            }
        }

        private static string ExtractAiOutcome(string message)
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

        private static bool ContainsIgnoreCase(string text, string value)
        {
            return TextFormatting.ContainsIgnoreCase(text, value);
        }

        private static string NormalizeReasonForAggregate(string value)
        {
            if (String.IsNullOrWhiteSpace(value)) return "";

            if (ContainsIgnoreCase(value, "unattended-agent context") ||
                ContainsIgnoreCase(value, "agent-process:") ||
                ContainsIgnoreCase(value, "agent-child-process:") ||
                ContainsIgnoreCase(value, "agent-parent:") ||
                ContainsIgnoreCase(value, "agent-package-tool:") ||
                ContainsIgnoreCase(value, "agent-workspace:") ||
                ContainsIgnoreCase(value, "agent-publish-root:") ||
                ContainsIgnoreCase(value, "approved-admin-task:") ||
                ContainsIgnoreCase(value, "secret-indicator:"))
            {
                return "Configured unattended-agent context was involved.";
            }

            if (ContainsIgnoreCase(value, "maintenance context"))
            {
                return "Configured maintenance context matched.";
            }

            return SanitizeText(value);
        }

        private static string SanitizeToken(string value)
        {
            if (String.IsNullOrWhiteSpace(value)) return "";
            return SanitizeText(value).Replace(" ", "_");
        }

        private static string SanitizeText(string value)
        {
            return SensitiveTextRedactor.RedactForAiPayload(value, true, true);
        }

        private static string TrimForSummary(string value, int maxChars)
        {
            if (String.IsNullOrWhiteSpace(value)) return "";
            if (value.Length <= maxChars) return value;
            if (maxChars <= 3) return value.Substring(0, maxChars);
            return value.Substring(0, maxChars - 3).TrimEnd() + "...";
        }

    }

    internal sealed class CompactAlertRecord
    {
        public DateTime TimestampUtc;
        public string RuleId;
        public string Category;
        public string Severity;
        public int Score;
        public string Title;
        public bool MaintenanceContext;
        public bool AgentContext;
        public string RemoteContext;
        public List<string> Why = new List<string>();
    }

    internal sealed class AlertAggregate
    {
        private const int SignificantScore = 60;

        public int ParseFailures;
        public int ExcludedRuleRecords;
        private int totalRecords;
        private int lowRecords;
        private int mediumRecords;
        private int highRecords;
        private int criticalRecords;
        private int maintenanceContextRecords;
        private int agentContextRecords;
        private int maxScore;
        private DateTime firstAlertUtc = DateTime.MinValue;
        private DateTime lastAlertUtc = DateTime.MinValue;
        private readonly List<CompactAlertRecord> records = new List<CompactAlertRecord>();
        private readonly Dictionary<string, AlertAggregateBucket> byCategory = new Dictionary<string, AlertAggregateBucket>(StringComparer.OrdinalIgnoreCase);
        private readonly Dictionary<string, AlertAggregateBucket> byRule = new Dictionary<string, AlertAggregateBucket>(StringComparer.OrdinalIgnoreCase);
        private readonly Dictionary<string, AlertAggregateBucket> bySeverity = new Dictionary<string, AlertAggregateBucket>(StringComparer.OrdinalIgnoreCase);
        private readonly Dictionary<string, AlertAggregateBucket> byRemoteContext = new Dictionary<string, AlertAggregateBucket>(StringComparer.OrdinalIgnoreCase);
        private readonly Dictionary<string, AlertReasonBucket> byReason = new Dictionary<string, AlertReasonBucket>(StringComparer.OrdinalIgnoreCase);

        public void Add(CompactAlertRecord record)
        {
            if (record == null) return;

            records.Add(record);
            totalRecords++;
            if (record.Score > maxScore) maxScore = record.Score;
            if (record.MaintenanceContext) maintenanceContextRecords++;
            if (record.AgentContext) agentContextRecords++;

            if (record.Score >= 90) criticalRecords++;
            else if (record.Score >= 75) highRecords++;
            else if (record.Score >= 60) mediumRecords++;
            else lowRecords++;

            if (record.TimestampUtc > DateTime.MinValue)
            {
                if (firstAlertUtc == DateTime.MinValue || record.TimestampUtc < firstAlertUtc) firstAlertUtc = record.TimestampUtc;
                if (lastAlertUtc == DateTime.MinValue || record.TimestampUtc > lastAlertUtc) lastAlertUtc = record.TimestampUtc;
            }

            Increment(byCategory, record.Category, record);
            Increment(byRule, record.RuleId, record);
            Increment(bySeverity, record.Severity, record);
            if (!String.IsNullOrWhiteSpace(record.RemoteContext))
            {
                Increment(byRemoteContext, record.RemoteContext, record);
            }

            if (record.Score >= SignificantScore)
            {
                foreach (string reason in record.Why)
                {
                    IncrementReason(byReason, reason, record);
                }
            }
        }

        public string ToSummary()
        {
            StringBuilder builder = new StringBuilder();
            builder.AppendLine("aggregate_scope=last_configured_alert_records_non_excluded");
            builder.AppendLine("significant_score_minimum=" + SignificantScore.ToString(CultureInfo.InvariantCulture));
            builder.AppendLine("window_records=" + totalRecords.ToString(CultureInfo.InvariantCulture) +
                " excluded_rule_records=" + ExcludedRuleRecords.ToString(CultureInfo.InvariantCulture) +
                " parse_failures=" + ParseFailures.ToString(CultureInfo.InvariantCulture) +
                " first_alert_utc=" + FormatDate(firstAlertUtc) +
                " last_alert_utc=" + FormatDate(lastAlertUtc));
            builder.AppendLine("score_buckets low=" + lowRecords.ToString(CultureInfo.InvariantCulture) +
                " medium=" + mediumRecords.ToString(CultureInfo.InvariantCulture) +
                " high=" + highRecords.ToString(CultureInfo.InvariantCulture) +
                " critical=" + criticalRecords.ToString(CultureInfo.InvariantCulture) +
                " max_score=" + maxScore.ToString(CultureInfo.InvariantCulture));
            builder.AppendLine("context_counts maintenance_context=" + maintenanceContextRecords.ToString(CultureInfo.InvariantCulture) +
                " agent_context=" + agentContextRecords.ToString(CultureInfo.InvariantCulture) +
                " non_maintenance=" + (totalRecords - maintenanceContextRecords).ToString(CultureInfo.InvariantCulture));
            AppendRuleRepetition(builder);
            AppendTrend(builder);
            AppendBuckets(builder, "by_severity", SortedBuckets(bySeverity), 6, false);
            AppendBuckets(builder, "by_category", SortedBuckets(byCategory), 8, false);
            AppendBuckets(builder, "top_rules_score_60_plus", SignificantRuleBuckets(), 8, true);
            AppendBuckets(builder, "top_remote_context_score_60_plus", SignificantRemoteContextBuckets(), 8, true);
            AppendReasons(builder, "top_reasons_score_60_plus", SortedReasons(byReason), 6);
            return builder.ToString();
        }

        private void AppendRuleRepetition(StringBuilder builder)
        {
            int repeated = 0;
            int single = 0;
            foreach (AlertAggregateBucket bucket in byRule.Values)
            {
                if (bucket.Count > 1) repeated++;
                else single++;
            }

            builder.AppendLine("rule_repetition distinct_rules=" + byRule.Count.ToString(CultureInfo.InvariantCulture) +
                " repeated_rule_ids=" + repeated.ToString(CultureInfo.InvariantCulture) +
                " single_rule_ids=" + single.ToString(CultureInfo.InvariantCulture));
        }

        private void AppendTrend(StringBuilder builder)
        {
            int midpoint = records.Count / 2;
            int firstCount = 0;
            int firstMax = 0;
            int secondCount = 0;
            int secondMax = 0;

            for (int index = 0; index < records.Count; index++)
            {
                CompactAlertRecord record = records[index];
                if (index < midpoint)
                {
                    firstCount++;
                    if (record.Score > firstMax) firstMax = record.Score;
                }
                else
                {
                    secondCount++;
                    if (record.Score > secondMax) secondMax = record.Score;
                }
            }

            builder.AppendLine("window_trend first_half_count=" + firstCount.ToString(CultureInfo.InvariantCulture) +
                " first_half_max=" + firstMax.ToString(CultureInfo.InvariantCulture) +
                " second_half_count=" + secondCount.ToString(CultureInfo.InvariantCulture) +
                " second_half_max=" + secondMax.ToString(CultureInfo.InvariantCulture));
        }

        private static void Increment(Dictionary<string, AlertAggregateBucket> buckets, string name, CompactAlertRecord record)
        {
            if (String.IsNullOrWhiteSpace(name)) name = "unknown";

            AlertAggregateBucket bucket;
            if (!buckets.TryGetValue(name, out bucket))
            {
                bucket = new AlertAggregateBucket();
                bucket.Name = name;
                buckets[name] = bucket;
            }

            bucket.Count++;
            if (record.Score > bucket.MaxScore) bucket.MaxScore = record.Score;
            if (record.MaintenanceContext) bucket.MaintenanceContext++;
            if (record.AgentContext) bucket.AgentContext++;
        }

        private static void IncrementReason(Dictionary<string, AlertReasonBucket> buckets, string reason, CompactAlertRecord record)
        {
            if (String.IsNullOrWhiteSpace(reason)) return;

            AlertReasonBucket bucket;
            if (!buckets.TryGetValue(reason, out bucket))
            {
                bucket = new AlertReasonBucket();
                bucket.Reason = reason;
                buckets[reason] = bucket;
            }

            bucket.Count++;
            if (record.Score > bucket.MaxScore) bucket.MaxScore = record.Score;
            if (record.MaintenanceContext) bucket.MaintenanceContext++;
            if (record.AgentContext) bucket.AgentContext++;
        }

        private List<AlertAggregateBucket> SignificantRuleBuckets()
        {
            List<AlertAggregateBucket> result = new List<AlertAggregateBucket>();
            foreach (AlertAggregateBucket bucket in byRule.Values)
            {
                if (bucket.MaxScore >= SignificantScore)
                {
                    result.Add(bucket);
                }
            }

            SortBuckets(result);
            return result;
        }

        private List<AlertAggregateBucket> SignificantRemoteContextBuckets()
        {
            List<AlertAggregateBucket> result = new List<AlertAggregateBucket>();
            foreach (AlertAggregateBucket bucket in byRemoteContext.Values)
            {
                if (bucket.MaxScore >= SignificantScore)
                {
                    result.Add(bucket);
                }
            }

            SortBuckets(result);
            return result;
        }

        private static List<AlertAggregateBucket> SortedBuckets(Dictionary<string, AlertAggregateBucket> buckets)
        {
            List<AlertAggregateBucket> result = new List<AlertAggregateBucket>(buckets.Values);
            SortBuckets(result);
            return result;
        }

        private static List<AlertReasonBucket> SortedReasons(Dictionary<string, AlertReasonBucket> buckets)
        {
            List<AlertReasonBucket> result = new List<AlertReasonBucket>(buckets.Values);
            result.Sort(delegate(AlertReasonBucket left, AlertReasonBucket right)
            {
                int countComparison = right.Count.CompareTo(left.Count);
                if (countComparison != 0) return countComparison;
                int scoreComparison = right.MaxScore.CompareTo(left.MaxScore);
                if (scoreComparison != 0) return scoreComparison;
                return String.Compare(left.Reason, right.Reason, StringComparison.OrdinalIgnoreCase);
            });
            return result;
        }

        private static void SortBuckets(List<AlertAggregateBucket> buckets)
        {
            buckets.Sort(delegate(AlertAggregateBucket left, AlertAggregateBucket right)
            {
                int countComparison = right.Count.CompareTo(left.Count);
                if (countComparison != 0) return countComparison;
                int scoreComparison = right.MaxScore.CompareTo(left.MaxScore);
                if (scoreComparison != 0) return scoreComparison;
                return String.Compare(left.Name, right.Name, StringComparison.OrdinalIgnoreCase);
            });
        }

        private static void AppendBuckets(StringBuilder builder, string title, List<AlertAggregateBucket> buckets, int limit, bool significantOnly)
        {
            builder.AppendLine(title + "_count=" + buckets.Count.ToString(CultureInfo.InvariantCulture));
            int count = Math.Min(limit, buckets.Count);
            for (int index = 0; index < count; index++)
            {
                AlertAggregateBucket bucket = buckets[index];
                if (significantOnly && bucket.MaxScore < SignificantScore) continue;
                builder.AppendLine(title + "=" + SanitizeTokenForAggregate(bucket.Name) +
                    " count=" + bucket.Count.ToString(CultureInfo.InvariantCulture) +
                    " max=" + bucket.MaxScore.ToString(CultureInfo.InvariantCulture) +
                    " maintenance_context=" + bucket.MaintenanceContext.ToString(CultureInfo.InvariantCulture) +
                    " agent_context=" + bucket.AgentContext.ToString(CultureInfo.InvariantCulture));
            }
        }

        private static void AppendReasons(StringBuilder builder, string title, List<AlertReasonBucket> buckets, int limit)
        {
            builder.AppendLine(title + "_count=" + buckets.Count.ToString(CultureInfo.InvariantCulture));
            int count = Math.Min(limit, buckets.Count);
            for (int index = 0; index < count; index++)
            {
                AlertReasonBucket bucket = buckets[index];
                builder.AppendLine(title + "=" + SanitizeTokenForAggregate(bucket.Reason) +
                    " count=" + bucket.Count.ToString(CultureInfo.InvariantCulture) +
                    " max=" + bucket.MaxScore.ToString(CultureInfo.InvariantCulture) +
                    " maintenance_context=" + bucket.MaintenanceContext.ToString(CultureInfo.InvariantCulture) +
                    " agent_context=" + bucket.AgentContext.ToString(CultureInfo.InvariantCulture));
            }
        }

        private static string SanitizeTokenForAggregate(string value)
        {
            if (String.IsNullOrWhiteSpace(value)) return "unknown";
            string sanitized = Regex.Replace(value, "\\s+", "_");
            return sanitized;
        }

        private static string FormatDate(DateTime value)
        {
            return value > DateTime.MinValue ? UtcTimestamp.Format(value) : "";
        }
    }

    internal sealed class AlertAggregateBucket
    {
        public string Name;
        public int Count;
        public int MaxScore;
        public int MaintenanceContext;
        public int AgentContext;
    }

    internal sealed class AlertReasonBucket
    {
        public string Reason;
        public int Count;
        public int MaxScore;
        public int MaintenanceContext;
        public int AgentContext;
    }
}
