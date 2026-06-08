using System;
using System.Collections;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Web.Script.Serialization;

namespace ArcaneEDR
{
    internal static class DetectionPolicyConsole
    {
        public static int Preview(string baseDirectory, string[] args)
        {
            MonitorConfig config = MonitorConfig.Load(baseDirectory);
            TimeSpan lookback = ParseLookback(args, TimeSpan.FromHours(24));
            int limit = ParseLimit(args, 20);
            string samplePath = FirstOptionValue(args, "--sample-alert", "--sample-json");
            string sampleRule = OptionValue(args, "--sample-rule", "");
            bool sampleMode = !String.IsNullOrWhiteSpace(samplePath) || !String.IsNullOrWhiteSpace(sampleRule);

            Console.WriteLine("Detection policy preview");
            Console.WriteLine("PolicyFile=" + config.DetectionPolicyFile);
            Console.WriteLine("Mode=" + (sampleMode ? "sample" : "recent-alerts"));
            if (!sampleMode) Console.WriteLine("Lookback=" + Describe(lookback));

            if (!config.EnableDetectionPolicy)
            {
                Console.WriteLine("Detection policy is disabled by EnableDetectionPolicy=false.");
                return 0;
            }

            DetectionPolicy policy = DetectionPolicy.Load(config.DetectionPolicyFile);
            if (!policy.FileFound)
            {
                Console.WriteLine("No detection policy file found. No entries would apply.");
                return 0;
            }

            foreach (string warning in policy.Warnings)
            {
                Console.WriteLine("[WARN] " + warning);
            }

            if (policy.Errors.Count > 0)
            {
                foreach (string error in policy.Errors)
                {
                    Console.WriteLine("[FAIL] " + error);
                }

                return 1;
            }

            Console.WriteLine("PolicyEntries=" + policy.Rules.Count.ToString(CultureInfo.InvariantCulture));

            List<Alert> alerts;
            if (!String.IsNullOrWhiteSpace(samplePath))
            {
                alerts = LoadSampleAlerts(samplePath);
                Console.WriteLine("SampleFile=" + samplePath);
                if (alerts.Count == 0)
                {
                    Console.WriteLine("No sample alerts could be read from the sample file.");
                    return 1;
                }
            }
            else if (!String.IsNullOrWhiteSpace(sampleRule))
            {
                alerts = new List<Alert>();
                alerts.Add(BuildSampleAlert(args, sampleRule));
                Console.WriteLine("SampleRule=" + sampleRule);
            }
            else
            {
                string alertsPath = Path.Combine(config.LogDirectory, "ArcaneAlerts.jsonl");
                if (!File.Exists(alertsPath))
                {
                    Console.WriteLine("No alert log found: " + alertsPath);
                    return 0;
                }

                alerts = LoadRecentAlerts(alertsPath, lookback);
                if (alerts.Count == 0)
                {
                    Console.WriteLine("No recent alerts found.");
                    return 0;
                }
            }

            DetectionPolicyEngine engine = new DetectionPolicyEngine(config, null);
            int matched = 0;
            foreach (Alert alert in alerts)
            {
                int originalScore = alert.Score;
                DetectionPolicyResult result = engine.ApplyPolicy(alert, policy);
                if (!result.HasMatches) continue;

                matched++;
                PrintMatch(alert, result, originalScore);

                if (matched >= limit) break;
            }

            Console.WriteLine("");
            Console.WriteLine("MatchedAlertsShown=" + matched.ToString(CultureInfo.InvariantCulture));
            if (matched == 0)
            {
                Console.WriteLine(sampleMode
                    ? "No policy entries matched the sample alert input."
                    : "No policy entries matched recent alerts in this window.");
            }

            return 0;
        }

        private static void PrintMatch(Alert alert, DetectionPolicyResult result, int originalScore)
        {
            Console.WriteLine("");
            Console.WriteLine(FormatTime(alert.TimestampUtc) +
                " rule=" + Safe(alert.RuleId) +
                " score=" + originalScore.ToString(CultureInfo.InvariantCulture) + "->" + alert.Score.ToString(CultureInfo.InvariantCulture) +
                " title=" + Compact(alert.Title, 96));
            Console.WriteLine("  external=" + ExternalRead(alert));
            foreach (DetectionPolicyAppliedRule applied in result.AppliedRules)
            {
                Console.WriteLine("  matched " + Safe(applied.Id) +
                    " action=" + Safe(applied.Action) +
                    " score=" + applied.ScoreBefore.ToString(CultureInfo.InvariantCulture) + "->" + applied.ScoreAfter.ToString(CultureInfo.InvariantCulture) +
                    " reason=" + Compact(applied.Reason, 140));
            }
        }

        private static List<Alert> LoadRecentAlerts(string path, TimeSpan lookback)
        {
            List<Alert> result = new List<Alert>();
            DateTime cutoffUtc = DateTime.UtcNow.Subtract(lookback);
            JavaScriptSerializer serializer = new JavaScriptSerializer();

            foreach (string line in File.ReadAllLines(path))
            {
                Alert alert = ParseAlert(serializer, line, true);
                if (alert == null || alert.TimestampUtc < cutoffUtc) continue;
                result.Add(alert);
            }

            result.Sort(delegate(Alert left, Alert right)
            {
                int timeComparison = right.TimestampUtc.CompareTo(left.TimestampUtc);
                if (timeComparison != 0) return timeComparison;
                return right.Score.CompareTo(left.Score);
            });

            return result;
        }

        private static List<Alert> LoadSampleAlerts(string path)
        {
            List<Alert> result = new List<Alert>();
            if (String.IsNullOrWhiteSpace(path) || !File.Exists(path)) return result;

            JavaScriptSerializer serializer = new JavaScriptSerializer();
            string text = File.ReadAllText(path);

            try
            {
                object parsed = serializer.DeserializeObject(text);
                IList list = parsed as IList;
                if (list != null)
                {
                    foreach (object item in list)
                    {
                        IDictionary map = item as IDictionary;
                        Alert alert = ParseAlertMap(map, false);
                        if (alert != null) result.Add(alert);
                    }

                    return result;
                }

                IDictionary root = parsed as IDictionary;
                if (root != null)
                {
                    IList alerts = DetectionPolicy.Value(root, "alerts") as IList;
                    if (alerts != null)
                    {
                        foreach (object item in alerts)
                        {
                            Alert alert = ParseAlertMap(item as IDictionary, false);
                            if (alert != null) result.Add(alert);
                        }

                        return result;
                    }

                    Alert single = ParseAlertMap(root, false);
                    if (single != null) result.Add(single);
                    return result;
                }
            }
            catch
            {
            }

            foreach (string line in text.Split(new[] { "\r\n", "\n" }, StringSplitOptions.RemoveEmptyEntries))
            {
                Alert alert = ParseAlert(serializer, line, false);
                if (alert != null) result.Add(alert);
            }

            return result;
        }

        private static Alert BuildSampleAlert(string[] args, string sampleRule)
        {
            int score = ParseIntOption(args, "--sample-score", 60);
            string title = OptionValue(args, "--sample-title", "Sample policy preview alert");
            string body = OptionValue(args, "--sample-body", "Sample alert generated for detection policy preview.");
            string entity = OptionValue(args, "--sample-entity", "");
            List<string> sampleFields = new List<string>();
            AddSampleField(sampleFields, "process", OptionValue(args, "--sample-process", ""));
            AddSampleField(sampleFields, "parent", OptionValue(args, "--sample-parent", ""));
            AddSampleField(sampleFields, "user", OptionValue(args, "--sample-user", ""));
            AddSampleField(sampleFields, "destination_domain", FirstOptionValue(args, "--sample-destination-domain", "--sample-domain", "--sample-destination"));
            AddSampleField(sampleFields, "ip", FirstOptionValue(args, "--sample-ip", "--sample-remote-ip"));
            AddSampleField(sampleFields, "port", FirstOptionValue(args, "--sample-port", "--sample-remote-port"));
            AddSampleField(sampleFields, "path", FirstOptionValue(args, "--sample-path", "--sample-path-prefix"));
            AddSampleField(sampleFields, "signer", OptionValue(args, "--sample-signer", ""));
            AddSampleField(sampleFields, "hash", OptionValue(args, "--sample-hash", ""));
            AddSampleField(sampleFields, "command", FirstOptionValue(args, "--sample-command", "--sample-command-line"));
            if (sampleFields.Count > 0)
            {
                string fields = String.Join(" ", sampleFields.ToArray());
                entity = String.IsNullOrWhiteSpace(entity)
                    ? fields
                    : entity + " " + fields;
                body = body + Environment.NewLine + "SampleContext: " + fields;
            }

            Alert alert = Alert.Create(
                sampleRule,
                title,
                score,
                body,
                "Review policy preview output.",
                "policy-preview|" + sampleRule);
            alert.Category = OptionValue(args, "--sample-category", AlertRuleCatalog.CategoryFor(sampleRule));
            alert.EntitySummary = String.IsNullOrWhiteSpace(entity) ? "sample=policy-preview" : entity;
            alert.TimestampUtc = DateTime.UtcNow;
            alert.SetScore(score);
            return alert;
        }

        private static void AddSampleField(List<string> fields, string name, string value)
        {
            if (fields == null || String.IsNullOrWhiteSpace(name) || String.IsNullOrWhiteSpace(value)) return;
            string normalized = value.Replace("\r", " ").Replace("\n", " ").Trim();
            while (normalized.IndexOf("  ", StringComparison.Ordinal) >= 0)
            {
                normalized = normalized.Replace("  ", " ");
            }

            if (normalized.Length > 0) fields.Add(name + "=" + normalized);
        }

        private static Alert ParseAlert(JavaScriptSerializer serializer, string line, bool requireTimestamp)
        {
            if (String.IsNullOrWhiteSpace(line)) return null;

            try
            {
                IDictionary parsed = serializer.DeserializeObject(line) as IDictionary;
                return ParseAlertMap(parsed, requireTimestamp);
            }
            catch
            {
                return null;
            }
        }

        private static Alert ParseAlertMap(IDictionary parsed, bool requireTimestamp)
        {
            if (parsed == null) return null;

            DateTime timestampUtc;
            if (!TryParseUtc(Read(parsed, "timestamp_utc"), out timestampUtc))
            {
                if (requireTimestamp) return null;
                timestampUtc = DateTime.UtcNow;
            }

            Alert alert = new Alert();
            alert.TimestampUtc = timestampUtc;
            alert.RuleId = FirstNonEmpty(Read(parsed, "rule_id"), Read(parsed, "rule"));
            alert.Category = Read(parsed, "category");
            if (String.IsNullOrWhiteSpace(alert.Category)) alert.Category = AlertRuleCatalog.CategoryFor(alert.RuleId);
            alert.Score = ReadInt(parsed, "score");
            alert.Severity = Read(parsed, "severity");
            if (String.IsNullOrWhiteSpace(alert.Severity)) alert.SetScore(alert.Score);
            alert.Title = Read(parsed, "title");
            alert.Body = Read(parsed, "body");
            alert.EntitySummary = FirstNonEmpty(Read(parsed, "entity"), Read(parsed, "entity_summary"));
            alert.Recommendation = Read(parsed, "recommendation");
            alert.PolicyContext = Read(parsed, "policy_context");
            alert.MaintenanceContext = ReadBool(parsed, "maintenance_context");
            alert.ExternalSuppressedByPolicy = ReadBool(parsed, "external_suppressed_by_policy");
            alert.ExternalForcedByPolicy = ReadBool(parsed, "external_forced_by_policy");
            return alert;
        }

        private static string ExternalRead(Alert alert)
        {
            if (alert.ExternalSuppressedByPolicy) return "suppressed_by_policy";
            if (alert.ExternalForcedByPolicy) return "forced_by_policy";
            return "unchanged";
        }

        private static TimeSpan ParseLookback(string[] args, TimeSpan fallback)
        {
            for (int index = 0; args != null && index < args.Length - 1; index++)
            {
                if (args[index].Equals("--last", StringComparison.OrdinalIgnoreCase))
                {
                    TimeSpan parsed;
                    if (TryParseDuration(args[index + 1], out parsed)) return parsed;
                }
            }

            return fallback;
        }

        private static int ParseLimit(string[] args, int fallback)
        {
            for (int index = 0; args != null && index < args.Length - 1; index++)
            {
                if (args[index].Equals("--limit", StringComparison.OrdinalIgnoreCase))
                {
                    int parsed;
                    if (Int32.TryParse(args[index + 1], out parsed) && parsed > 0) return parsed;
                }
            }

            return fallback;
        }

        private static string FirstOptionValue(string[] args, string firstName, string secondName)
        {
            string value = OptionValue(args, firstName, "");
            return String.IsNullOrWhiteSpace(value) ? OptionValue(args, secondName, "") : value;
        }

        private static string FirstOptionValue(string[] args, string firstName, string secondName, string thirdName)
        {
            string value = FirstOptionValue(args, firstName, secondName);
            return String.IsNullOrWhiteSpace(value) ? OptionValue(args, thirdName, "") : value;
        }

        private static string OptionValue(string[] args, string name, string fallback)
        {
            if (args == null || String.IsNullOrWhiteSpace(name)) return fallback;
            string equalsPrefix = name + "=";
            for (int index = 0; index < args.Length; index++)
            {
                if (args[index].Equals(name, StringComparison.OrdinalIgnoreCase) &&
                    index + 1 < args.Length)
                {
                    return args[index + 1];
                }

                if (args[index].StartsWith(equalsPrefix, StringComparison.OrdinalIgnoreCase))
                {
                    return args[index].Substring(equalsPrefix.Length);
                }
            }

            return fallback;
        }

        private static int ParseIntOption(string[] args, string name, int fallback)
        {
            int parsed;
            return Int32.TryParse(OptionValue(args, name, ""), out parsed) ? parsed : fallback;
        }

        private static bool TryParseDuration(string value, out TimeSpan result)
        {
            result = TimeSpan.Zero;
            if (String.IsNullOrWhiteSpace(value)) return false;

            string trimmed = value.Trim().ToLowerInvariant();
            double number;
            if (trimmed.EndsWith("m", StringComparison.OrdinalIgnoreCase) &&
                Double.TryParse(trimmed.Substring(0, trimmed.Length - 1), NumberStyles.Float, CultureInfo.InvariantCulture, out number))
            {
                result = TimeSpan.FromMinutes(number);
                return number > 0;
            }

            if (trimmed.EndsWith("h", StringComparison.OrdinalIgnoreCase) &&
                Double.TryParse(trimmed.Substring(0, trimmed.Length - 1), NumberStyles.Float, CultureInfo.InvariantCulture, out number))
            {
                result = TimeSpan.FromHours(number);
                return number > 0;
            }

            if (trimmed.EndsWith("d", StringComparison.OrdinalIgnoreCase) &&
                Double.TryParse(trimmed.Substring(0, trimmed.Length - 1), NumberStyles.Float, CultureInfo.InvariantCulture, out number))
            {
                result = TimeSpan.FromDays(number);
                return number > 0;
            }

            return TimeSpan.TryParse(value, out result) && result > TimeSpan.Zero;
        }

        private static string Describe(TimeSpan value)
        {
            if (value.TotalDays >= 1 && value.TotalDays == Math.Floor(value.TotalDays))
            {
                return value.TotalDays.ToString("0", CultureInfo.InvariantCulture) + "d";
            }

            if (value.TotalHours >= 1 && value.TotalHours == Math.Floor(value.TotalHours))
            {
                return value.TotalHours.ToString("0", CultureInfo.InvariantCulture) + "h";
            }

            return value.TotalMinutes.ToString("0", CultureInfo.InvariantCulture) + "m";
        }

        private static bool TryParseUtc(string value, out DateTime result)
        {
            result = DateTime.MinValue;
            if (String.IsNullOrWhiteSpace(value)) return false;

            DateTime parsed;
            if (!DateTime.TryParse(value, CultureInfo.InvariantCulture, DateTimeStyles.AdjustToUniversal, out parsed))
            {
                return false;
            }

            result = parsed.ToUniversalTime();
            return true;
        }

        private static string Read(IDictionary parsed, string key)
        {
            if (parsed == null) return "";
            foreach (DictionaryEntry entry in parsed)
            {
                string entryKey = entry.Key == null ? "" : entry.Key.ToString();
                if (entryKey.Equals(key, StringComparison.OrdinalIgnoreCase))
                {
                    return entry.Value == null ? "" : entry.Value.ToString();
                }
            }

            return "";
        }

        private static string FirstNonEmpty(string first, string second)
        {
            return String.IsNullOrWhiteSpace(first) ? (second ?? "") : first;
        }

        private static int ReadInt(IDictionary parsed, string key)
        {
            int value;
            return Int32.TryParse(Read(parsed, key), out value) ? value : 0;
        }

        private static bool ReadBool(IDictionary parsed, string key)
        {
            bool value;
            return Boolean.TryParse(Read(parsed, key), out value) && value;
        }

        private static string FormatTime(DateTime utc)
        {
            return utc.ToString("yyyy-MM-ddTHH:mm:ssZ", CultureInfo.InvariantCulture);
        }

        private static string Safe(string value)
        {
            return String.IsNullOrWhiteSpace(value) ? "unknown" : value.Trim();
        }

        private static string Compact(string value, int maxLength)
        {
            if (String.IsNullOrWhiteSpace(value)) return "unknown";
            string compact = value.Replace("\r", " ").Replace("\n", " ").Replace("\t", " ").Trim();
            while (compact.IndexOf("  ", StringComparison.Ordinal) >= 0)
            {
                compact = compact.Replace("  ", " ");
            }

            if (compact.Length <= maxLength) return compact;
            if (maxLength <= 3) return compact.Substring(0, maxLength);
            return compact.Substring(0, maxLength - 3) + "...";
        }
    }
}
