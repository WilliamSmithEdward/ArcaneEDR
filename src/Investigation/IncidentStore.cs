using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Web.Script.Serialization;

namespace ArcaneEDR
{
    internal sealed class IncidentStore
    {
        private readonly MonitorConfig config;
        private readonly FileLogger logger;
        private readonly object gate = new object();

        public IncidentStore(MonitorConfig config, FileLogger logger)
        {
            this.config = config;
            this.logger = logger;
        }

        public void Record(Alert alert)
        {
            if (!ShouldRecord(alert)) return;

            try
            {
                lock (gate)
                {
                    Directory.CreateDirectory(Path.GetDirectoryName(config.IncidentStoreFile));
                    IncidentRecord record = BuildRecord(alert);
                    record.incident_id = FindRecentIncidentId(record.group_key, alert.TimestampUtc);
                    if (String.IsNullOrWhiteSpace(record.incident_id))
                    {
                        record.incident_id = NewIncidentId(record.group_key, alert.TimestampUtc);
                    }

                    File.AppendAllText(config.IncidentStoreFile, Serialize(record) + Environment.NewLine);
                }
            }
            catch (Exception ex)
            {
                if (logger != null)
                {
                    logger.Warn("Incident record failed: " + ex.Message);
                }
            }
        }

        public List<IncidentSummary> ListSummaries(TimeSpan lookback)
        {
            DateTime cutoff = DateTime.UtcNow.Subtract(lookback);
            Dictionary<string, IncidentSummary> summaries = new Dictionary<string, IncidentSummary>(StringComparer.OrdinalIgnoreCase);

            foreach (IncidentRecord record in ReadRecords(cutoff))
            {
                DateTime observedUtc;
                if (!TryParseUtc(record.observed_utc, out observedUtc)) continue;

                IncidentSummary summary;
                if (!summaries.TryGetValue(record.incident_id, out summary))
                {
                    summary = new IncidentSummary();
                    summaries[record.incident_id] = summary;
                }

                summary.Apply(record, observedUtc);
            }

            List<IncidentSummary> result = new List<IncidentSummary>(summaries.Values);
            result.Sort(delegate(IncidentSummary left, IncidentSummary right)
            {
                return right.LastSeenUtc.CompareTo(left.LastSeenUtc);
            });
            return result;
        }

        public List<IncidentRecord> Timeline(string incidentId)
        {
            List<IncidentRecord> result = new List<IncidentRecord>();
            if (String.IsNullOrWhiteSpace(incidentId)) return result;

            foreach (IncidentRecord record in ReadRecords(DateTime.MinValue))
            {
                if (record.incident_id != null &&
                    record.incident_id.Equals(incidentId, StringComparison.OrdinalIgnoreCase))
                {
                    result.Add(record);
                }
            }

            result.Sort(delegate(IncidentRecord left, IncidentRecord right)
            {
                DateTime leftTime;
                DateTime rightTime;
                TryParseUtc(left.observed_utc, out leftTime);
                TryParseUtc(right.observed_utc, out rightTime);
                return leftTime.CompareTo(rightTime);
            });
            return result;
        }

        private bool ShouldRecord(Alert alert)
        {
            if (alert == null) return false;
            if (config == null || !config.EnableIncidentGrouping) return false;
            if (String.IsNullOrWhiteSpace(config.IncidentStoreFile)) return false;
            if (alert.Score < config.IncidentMinimumScore) return false;

            string ruleId = alert.RuleId ?? "";
            return !ruleId.Equals("SERVICE-STARTED", StringComparison.OrdinalIgnoreCase) &&
                !ruleId.Equals("SERVICE-STOPPED", StringComparison.OrdinalIgnoreCase) &&
                !ruleId.Equals("SERVICE-DAILY-SUMMARY", StringComparison.OrdinalIgnoreCase) &&
                !ruleId.Equals("SERVICE-HEALTH-TEST", StringComparison.OrdinalIgnoreCase) &&
                !ruleId.Equals("OPENAI-LOG-ANALYSIS-TEST", StringComparison.OrdinalIgnoreCase) &&
                !ruleId.Equals("TEST-ALERT-DELIVERY", StringComparison.OrdinalIgnoreCase);
        }

        private IncidentRecord BuildRecord(Alert alert)
        {
            string text = AlertText(alert);
            string category = AlertRulePolicy.AlertCategory(alert);
            string user = FirstNonEmpty(
                ExtractField(text, "user="),
                ExtractField(text, "account="),
                ExtractField(text, "target_user="),
                ExtractField(text, "subject_user="),
                "unknown");
            string process = FirstNonEmpty(
                ExtractField(text, "process_name="),
                ExtractField(text, "process="),
                ExtractField(text, "image="),
                ExtractField(text, "parent_process_name="),
                ExtractField(text, "parent_process="),
                ExtractField(text, "parent="),
                category);

            if (category.Equals("Persistence", StringComparison.OrdinalIgnoreCase))
            {
                process = FirstNonEmpty(ExtractField(text, "name="), process);
            }

            process = FileName(process);
            string groupKey = GroupKey(category, user, process);

            return new IncidentRecord
            {
                observed_utc = FormatUtc(alert.TimestampUtc),
                group_key = groupKey,
                host = Environment.MachineName,
                category = category,
                user = user,
                process = process,
                rule_id = alert.RuleId,
                severity = alert.Severity,
                score = alert.Score,
                title = Compact(alert.Title, 180),
                why = Compact(WhyText(alert), 500),
                entity = Compact(alert.EntitySummary, 800),
                recommendation = Compact(alert.Recommendation, 500)
            };
        }

        private string FindRecentIncidentId(string groupKey, DateTime observedUtc)
        {
            DateTime cutoff = observedUtc.AddMinutes(-Math.Max(1, config.IncidentWindowMinutes));
            string[] lines = ReadAllLines();
            for (int index = lines.Length - 1; index >= 0; index--)
            {
                IncidentRecord record;
                if (!TryDeserialize(lines[index], out record)) continue;
                if (record.group_key == null ||
                    !record.group_key.Equals(groupKey, StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }

                DateTime previousUtc;
                if (!TryParseUtc(record.observed_utc, out previousUtc)) continue;
                if (previousUtc >= cutoff) return record.incident_id;
            }

            return "";
        }

        private IEnumerable<IncidentRecord> ReadRecords(DateTime cutoffUtc)
        {
            foreach (string line in ReadAllLines())
            {
                IncidentRecord record;
                if (!TryDeserialize(line, out record)) continue;

                DateTime observedUtc;
                if (!TryParseUtc(record.observed_utc, out observedUtc)) continue;
                if (observedUtc < cutoffUtc) continue;

                yield return record;
            }
        }

        private string[] ReadAllLines()
        {
            try
            {
                if (!File.Exists(config.IncidentStoreFile)) return new string[0];
                return File.ReadAllLines(config.IncidentStoreFile);
            }
            catch (Exception ex)
            {
                if (logger != null)
                {
                    logger.Warn("Incident store read failed: " + ex.Message);
                }

                return new string[0];
            }
        }

        private static string Serialize(IncidentRecord record)
        {
            JavaScriptSerializer serializer = new JavaScriptSerializer();
            return serializer.Serialize(record);
        }

        private static bool TryDeserialize(string line, out IncidentRecord record)
        {
            record = null;
            if (String.IsNullOrWhiteSpace(line)) return false;

            try
            {
                JavaScriptSerializer serializer = new JavaScriptSerializer();
                record = serializer.Deserialize<IncidentRecord>(line);
                return record != null && !String.IsNullOrWhiteSpace(record.incident_id);
            }
            catch
            {
                return false;
            }
        }

        private static string NewIncidentId(string groupKey, DateTime observedUtc)
        {
            return "INC-" + observedUtc.ToUniversalTime().ToString("yyyyMMddHHmmss", CultureInfo.InvariantCulture) + "-" + ShortHash(groupKey);
        }

        private static string GroupKey(string category, string user, string process)
        {
            return Environment.MachineName.ToLowerInvariant() + "|" +
                NormalizeKeyPart(category) + "|" +
                NormalizeKeyPart(user) + "|" +
                NormalizeKeyPart(process);
        }

        private static string NormalizeKeyPart(string value)
        {
            if (String.IsNullOrWhiteSpace(value)) return "unknown";
            return value.Trim().ToLowerInvariant()
                .Replace("\\", "/")
                .Replace(" ", "_")
                .Replace("|", "_")
                .Replace("\r", "")
                .Replace("\n", "");
        }

        private static string ExtractField(string text, string fieldName)
        {
            if (String.IsNullOrWhiteSpace(text) || String.IsNullOrWhiteSpace(fieldName)) return "";

            int index = text.IndexOf(fieldName, StringComparison.OrdinalIgnoreCase);
            while (index >= 0)
            {
                int start = index + fieldName.Length;
                string value = ReadToken(text, start);
                if (!String.IsNullOrWhiteSpace(value)) return value;
                index = text.IndexOf(fieldName, index + fieldName.Length, StringComparison.OrdinalIgnoreCase);
            }

            return "";
        }

        private static string ReadToken(string text, int start)
        {
            int index = start;
            while (index < text.Length && Char.IsWhiteSpace(text[index]))
            {
                index++;
            }

            if (index < text.Length && (text[index] == '"' || text[index] == '\''))
            {
                char quote = text[index];
                index++;
                int endQuote = text.IndexOf(quote, index);
                if (endQuote > index) return text.Substring(index, endQuote - index).Trim();
            }

            int end = index;
            while (end < text.Length && !IsTokenBoundary(text[end]))
            {
                end++;
            }

            return end > index ? text.Substring(index, end - index).Trim() : "";
        }

        private static bool IsTokenBoundary(char value)
        {
            return Char.IsWhiteSpace(value) ||
                value == '|' ||
                value == ',' ||
                value == ';' ||
                value == ')' ||
                value == '(' ||
                value == '\r' ||
                value == '\n';
        }

        private static string FirstNonEmpty(params string[] values)
        {
            foreach (string value in values)
            {
                if (!String.IsNullOrWhiteSpace(value)) return value;
            }

            return "";
        }

        private static string FileName(string value)
        {
            if (String.IsNullOrWhiteSpace(value)) return "unknown";
            string cleaned = value.Trim().Trim('"');
            int slash = Math.Max(cleaned.LastIndexOf('\\'), cleaned.LastIndexOf('/'));
            return slash >= 0 && slash + 1 < cleaned.Length ? cleaned.Substring(slash + 1) : cleaned;
        }

        private static string AlertText(Alert alert)
        {
            return (alert.RuleId ?? "") + " " +
                (alert.Title ?? "") + " " +
                (alert.Body ?? "") + " " +
                (alert.EntitySummary ?? "");
        }

        private static string WhyText(Alert alert)
        {
            if (alert.Why == null || alert.Why.Count == 0) return "";
            return String.Join("; ", alert.Why.ToArray());
        }

        private static string Compact(string value, int maxLength)
        {
            if (String.IsNullOrWhiteSpace(value)) return "";
            string compact = value.Replace("\r", " ").Replace("\n", " ").Trim();
            if (compact.Length <= maxLength) return compact;
            return compact.Substring(0, maxLength) + "...";
        }

        private static string ShortHash(string value)
        {
            using (SHA256 sha = SHA256.Create())
            {
                byte[] hash = sha.ComputeHash(Encoding.UTF8.GetBytes(value ?? ""));
                StringBuilder builder = new StringBuilder();
                for (int index = 0; index < 4 && index < hash.Length; index++)
                {
                    builder.Append(hash[index].ToString("x2", CultureInfo.InvariantCulture));
                }

                return builder.ToString();
            }
        }

        internal static string FormatUtc(DateTime value)
        {
            return value.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ", CultureInfo.InvariantCulture);
        }

        internal static bool TryParseUtc(string value, out DateTime parsed)
        {
            parsed = DateTime.MinValue;
            if (String.IsNullOrWhiteSpace(value)) return false;

            if (DateTime.TryParse(value, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out parsed))
            {
                parsed = parsed.ToUniversalTime();
                return true;
            }

            return false;
        }
    }
}
