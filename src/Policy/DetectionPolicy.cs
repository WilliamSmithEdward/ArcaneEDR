using System;
using System.Collections;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Net;
using System.Text.RegularExpressions;
using System.Web.Script.Serialization;

namespace ArcaneEDR
{
    internal sealed class DetectionPolicy
    {
        public readonly List<DetectionPolicyRule> Rules = new List<DetectionPolicyRule>();
        public readonly List<string> Warnings = new List<string>();
        public readonly List<string> Errors = new List<string>();
        public string Path;
        public bool FileFound;

        public static DetectionPolicy Load(string path)
        {
            DetectionPolicy policy = new DetectionPolicy();
            policy.Path = path ?? "";

            if (String.IsNullOrWhiteSpace(path) || !File.Exists(path))
            {
                policy.FileFound = false;
                return policy;
            }

            policy.FileFound = true;

            try
            {
                string json = File.ReadAllText(path);
                JavaScriptSerializer serializer = new JavaScriptSerializer();
                object parsed = serializer.DeserializeObject(json);
                IList entries = EntriesFromRoot(parsed, policy);
                if (entries == null)
                {
                    policy.Errors.Add("Detection policy file must contain a JSON array or an object with a policies array.");
                    return policy;
                }

                int index = 0;
                foreach (object entry in entries)
                {
                    index++;
                    IDictionary map = entry as IDictionary;
                    if (map == null)
                    {
                        policy.Errors.Add("Detection policy entry " + index.ToString(CultureInfo.InvariantCulture) + " must be a JSON object.");
                        continue;
                    }

                    DetectionPolicyRule rule = ParseRule(map, index, policy);
                    if (rule != null)
                    {
                        policy.Rules.Add(rule);
                    }
                }
            }
            catch (Exception ex)
            {
                policy.Errors.Add("Detection policy file failed to parse: " + ex.Message);
            }

            return policy;
        }

        private static IList EntriesFromRoot(object parsed, DetectionPolicy policy)
        {
            IList direct = parsed as IList;
            if (direct != null) return direct;

            IDictionary root = parsed as IDictionary;
            if (root == null) return null;

            foreach (DictionaryEntry entry in root)
            {
                string key = Key(entry.Key);
                if (!key.Equals("policies", StringComparison.OrdinalIgnoreCase) &&
                    !key.Equals("rules", StringComparison.OrdinalIgnoreCase) &&
                    !key.Equals("detection_policies", StringComparison.OrdinalIgnoreCase) &&
                    !key.Equals("detectionPolicies", StringComparison.OrdinalIgnoreCase) &&
                    !key.Equals("remote_endpoint_policies", StringComparison.OrdinalIgnoreCase) &&
                    !key.Equals("remoteEndpointPolicies", StringComparison.OrdinalIgnoreCase) &&
                    !key.Equals("allowlists", StringComparison.OrdinalIgnoreCase) &&
                    !key.Equals("blocklists", StringComparison.OrdinalIgnoreCase) &&
                    !key.Equals("response_policy", StringComparison.OrdinalIgnoreCase) &&
                    !key.Equals("responsePolicy", StringComparison.OrdinalIgnoreCase) &&
                    !key.Equals("schema", StringComparison.OrdinalIgnoreCase) &&
                    !key.Equals("version", StringComparison.OrdinalIgnoreCase) &&
                    !key.Equals("description", StringComparison.OrdinalIgnoreCase))
                {
                    policy.Warnings.Add("Detection policy root contains an unknown field: " + key);
                }
            }

            object policies = Value(root, "detection_policies");
            if (policies == null) policies = Value(root, "detectionPolicies");
            if (policies == null) policies = Value(root, "policies");
            if (policies == null) policies = Value(root, "rules");
            return policies as IList;
        }

        private static DetectionPolicyRule ParseRule(IDictionary map, int index, DetectionPolicy policy)
        {
            DetectionPolicyRule rule = new DetectionPolicyRule();
            rule.Index = index;
            rule.Id = ReadString(map, "id");
            if (String.IsNullOrWhiteSpace(rule.Id))
            {
                rule.Id = "policy-" + index.ToString(CultureInfo.InvariantCulture);
                policy.Warnings.Add("Detection policy entry " + index.ToString(CultureInfo.InvariantCulture) + " is missing id; using " + rule.Id + ".");
            }

            rule.Enabled = ReadBool(map, "enabled", true);
            rule.Action = CanonicalAction(ReadString(map, "action"));
            rule.Reason = ReadString(map, "reason");
            rule.Owner = ReadString(map, "owner");
            rule.Tag = ReadString(map, "tag");
            rule.ScoreDelta = ReadInt(map, "score_delta", 0, out rule.HasScoreDelta);
            rule.SetScore = ReadInt(map, "score", 0, out rule.HasSetScore);

            string expires = ReadString(map, "expires_utc");
            if (!String.IsNullOrWhiteSpace(expires))
            {
                DateTime parsedExpires;
                if (DateTime.TryParse(expires, CultureInfo.InvariantCulture, DateTimeStyles.AdjustToUniversal, out parsedExpires))
                {
                    rule.HasExpiresUtc = true;
                    rule.ExpiresUtc = parsedExpires.ToUniversalTime();
                    if (rule.ExpiresUtc < DateTime.UtcNow)
                    {
                        policy.Warnings.Add("Detection policy entry " + rule.Id + " is expired and will not apply.");
                    }
                }
                else
                {
                    policy.Errors.Add("Detection policy entry " + rule.Id + " has invalid expires_utc.");
                }
            }

            ValidateRuleTopFields(map, rule, policy);
            ValidateAction(rule, policy);
            if (String.IsNullOrWhiteSpace(rule.Reason))
            {
                policy.Warnings.Add("Detection policy entry " + rule.Id + " should include a plain-English reason.");
            }

            IDictionary matchMap = Value(map, "match") as IDictionary;
            if (matchMap == null)
            {
                policy.Warnings.Add("Detection policy entry " + rule.Id + " has no match object and will not match any alert.");
                rule.Match = new DetectionPolicyMatch();
            }
            else
            {
                rule.Match = DetectionPolicyMatch.Parse(matchMap, rule.Id, policy);
            }

            if (!rule.Match.HasAnyCriterion)
            {
                policy.Warnings.Add("Detection policy entry " + rule.Id + " has no match criteria and will not match any alert.");
            }
            else if (rule.Match.CriterionCount <= 1 && IsRiskyBroadAction(rule.Action))
            {
                policy.Warnings.Add("Detection policy entry " + rule.Id + " is broad; add another match field before relying on it for tuning.");
            }

            return rule;
        }

        private static void ValidateRuleTopFields(IDictionary map, DetectionPolicyRule rule, DetectionPolicy policy)
        {
            foreach (DictionaryEntry entry in map)
            {
                string key = Key(entry.Key);
                if (key.Equals("id", StringComparison.OrdinalIgnoreCase) ||
                    key.Equals("enabled", StringComparison.OrdinalIgnoreCase) ||
                    key.Equals("action", StringComparison.OrdinalIgnoreCase) ||
                    key.Equals("reason", StringComparison.OrdinalIgnoreCase) ||
                    key.Equals("owner", StringComparison.OrdinalIgnoreCase) ||
                    key.Equals("expires_utc", StringComparison.OrdinalIgnoreCase) ||
                    key.Equals("score_delta", StringComparison.OrdinalIgnoreCase) ||
                    key.Equals("score", StringComparison.OrdinalIgnoreCase) ||
                    key.Equals("tag", StringComparison.OrdinalIgnoreCase) ||
                    key.Equals("match", StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }

                policy.Warnings.Add("Detection policy entry " + rule.Id + " contains an unknown field: " + key);
            }
        }

        private static void ValidateAction(DetectionPolicyRule rule, DetectionPolicy policy)
        {
            if (String.IsNullOrWhiteSpace(rule.Action))
            {
                policy.Errors.Add("Detection policy entry " + rule.Id + " is missing action.");
                return;
            }

            if (!IsSupportedAction(rule.Action))
            {
                policy.Errors.Add("Detection policy entry " + rule.Id + " has unsupported action: " + rule.Action);
                return;
            }

            if ((rule.Action.Equals("lower_score", StringComparison.OrdinalIgnoreCase) ||
                 rule.Action.Equals("raise_score", StringComparison.OrdinalIgnoreCase)) &&
                !rule.HasScoreDelta && !rule.HasSetScore)
            {
                policy.Warnings.Add("Detection policy entry " + rule.Id + " uses " + rule.Action + " without score_delta or score; a default delta will be used.");
            }
        }

        private static bool IsRiskyBroadAction(string action)
        {
            return action.Equals("trusted_context", StringComparison.OrdinalIgnoreCase) ||
                action.Equals("lower_score", StringComparison.OrdinalIgnoreCase) ||
                action.Equals("suppress_external", StringComparison.OrdinalIgnoreCase);
        }

        private static bool IsSupportedAction(string action)
        {
            return action.Equals("trusted_context", StringComparison.OrdinalIgnoreCase) ||
                action.Equals("lower_score", StringComparison.OrdinalIgnoreCase) ||
                action.Equals("suppress_external", StringComparison.OrdinalIgnoreCase) ||
                action.Equals("raise_score", StringComparison.OrdinalIgnoreCase) ||
                action.Equals("force_alert", StringComparison.OrdinalIgnoreCase) ||
                action.Equals("tag_only", StringComparison.OrdinalIgnoreCase);
        }

        private static string CanonicalAction(string action)
        {
            if (action == null) return "";
            return action.Trim().Replace("-", "_").Replace(" ", "_").ToLowerInvariant();
        }

        internal static object Value(IDictionary map, string key)
        {
            if (map == null || String.IsNullOrWhiteSpace(key)) return null;
            foreach (DictionaryEntry entry in map)
            {
                if (Key(entry.Key).Equals(key, StringComparison.OrdinalIgnoreCase))
                {
                    return entry.Value;
                }
            }

            return null;
        }

        internal static string ReadString(IDictionary map, string key)
        {
            object value = Value(map, key);
            return value == null ? "" : value.ToString().Trim();
        }

        internal static bool ReadBool(IDictionary map, string key, bool fallback)
        {
            object value = Value(map, key);
            if (value == null) return fallback;
            if (value is bool) return (bool)value;

            bool parsed;
            return Boolean.TryParse(value.ToString(), out parsed) ? parsed : fallback;
        }

        internal static int ReadInt(IDictionary map, string key, int fallback, out bool found)
        {
            found = false;
            object value = Value(map, key);
            if (value == null) return fallback;
            found = true;

            int parsed;
            return Int32.TryParse(value.ToString(), NumberStyles.Integer, CultureInfo.InvariantCulture, out parsed)
                ? parsed
                : fallback;
        }

        internal static List<string> ReadStringList(IDictionary map, string key)
        {
            List<string> result = new List<string>();
            object value = Value(map, key);
            AddStringValues(result, value);
            return result;
        }

        internal static void AddStringValues(List<string> result, object value)
        {
            if (result == null || value == null) return;

            IList list = value as IList;
            if (list != null)
            {
                foreach (object item in list)
                {
                    AddStringValues(result, item);
                }

                return;
            }

            string text = value.ToString();
            foreach (string part in text.Split(','))
            {
                string trimmed = part.Trim();
                if (trimmed.Length > 0) result.Add(trimmed);
            }
        }

        internal static string Key(object key)
        {
            return key == null ? "" : key.ToString();
        }
    }

    internal sealed class DetectionPolicyRule
    {
        public int Index;
        public string Id;
        public bool Enabled;
        public string Action;
        public string Reason;
        public string Owner;
        public bool HasExpiresUtc;
        public DateTime ExpiresUtc;
        public bool HasScoreDelta;
        public int ScoreDelta;
        public bool HasSetScore;
        public int SetScore;
        public string Tag;
        public DetectionPolicyMatch Match = new DetectionPolicyMatch();

        public bool IsExpired(DateTime nowUtc)
        {
            return HasExpiresUtc && ExpiresUtc <= nowUtc;
        }

        public bool Matches(Alert alert)
        {
            if (!Enabled || alert == null || IsExpired(DateTime.UtcNow)) return false;
            return Match != null && Match.Matches(alert);
        }
    }

    internal sealed class DetectionPolicyMatch
    {
        public readonly List<string> RuleIds = new List<string>();
        public readonly List<string> Categories = new List<string>();
        public readonly List<string> ProcessNames = new List<string>();
        public readonly List<string> ParentProcesses = new List<string>();
        public readonly List<string> Signers = new List<string>();
        public readonly List<string> PathPrefixes = new List<string>();
        public readonly List<string> CommandTerms = new List<string>();
        public readonly List<string> Users = new List<string>();
        public readonly List<string> DestinationDomains = new List<string>();
        public readonly List<string> IpCidrs = new List<string>();
        public readonly List<CidrRange> ParsedCidrs = new List<CidrRange>();
        public readonly List<string> Ports = new List<string>();
        public readonly List<string> Hashes = new List<string>();
        public readonly List<string> TextContains = new List<string>();

        public bool HasAnyCriterion
        {
            get { return CriterionCount > 0; }
        }

        public int CriterionCount
        {
            get
            {
                int count = 0;
                if (RuleIds.Count > 0) count++;
                if (Categories.Count > 0) count++;
                if (ProcessNames.Count > 0) count++;
                if (ParentProcesses.Count > 0) count++;
                if (Signers.Count > 0) count++;
                if (PathPrefixes.Count > 0) count++;
                if (CommandTerms.Count > 0) count++;
                if (Users.Count > 0) count++;
                if (DestinationDomains.Count > 0) count++;
                if (ParsedCidrs.Count > 0) count++;
                if (Ports.Count > 0) count++;
                if (Hashes.Count > 0) count++;
                if (TextContains.Count > 0) count++;
                return count;
            }
        }

        public static DetectionPolicyMatch Parse(IDictionary map, string ruleId, DetectionPolicy policy)
        {
            DetectionPolicyMatch match = new DetectionPolicyMatch();
            foreach (DictionaryEntry entry in map)
            {
                string key = DetectionPolicy.Key(entry.Key);
                string canonical = CanonicalMatchField(key);
                if (String.IsNullOrWhiteSpace(canonical))
                {
                    policy.Warnings.Add("Detection policy entry " + ruleId + " match contains an unknown field: " + key);
                    continue;
                }

                List<string> values = new List<string>();
                DetectionPolicy.AddStringValues(values, entry.Value);
                AddValues(match, canonical, values, ruleId, policy);
            }

            return match;
        }

        public bool Matches(Alert alert)
        {
            string text = AlertText(alert);
            string normalizedText = Normalize(text);

            if (RuleIds.Count > 0 && !AnyPatternMatches(RuleIds, alert.RuleId)) return false;
            if (Categories.Count > 0 && !AnyPatternMatches(Categories, AlertRulePolicy.AlertCategory(alert))) return false;
            if (ProcessNames.Count > 0 && !AnyFieldValueMatches(text, new[] { "process=", "process_name=", "image=" }, ProcessNames)) return false;
            if (ParentProcesses.Count > 0 && !AnyFieldValueMatches(text, new[] { "parent=", "parent_process=", "parent_process_name=" }, ParentProcesses)) return false;
            if (Signers.Count > 0 && !AnyContains(normalizedText, Signers)) return false;
            if (PathPrefixes.Count > 0 && !AnyPathPrefixMatches(normalizedText, PathPrefixes)) return false;
            if (CommandTerms.Count > 0 && !AllContains(normalizedText, CommandTerms)) return false;
            if (Users.Count > 0 && !AnyFieldValueMatches(text, new[] { "user=", "process_user=", "subject=", "account=" }, Users)) return false;
            if (DestinationDomains.Count > 0 && !AnyContains(normalizedText, DestinationDomains)) return false;
            if (ParsedCidrs.Count > 0 && !AnyCidrMatches(text, ParsedCidrs)) return false;
            if (Ports.Count > 0 && !AnyPortMatches(text, Ports)) return false;
            if (Hashes.Count > 0 && !AnyContains(normalizedText, Hashes)) return false;
            if (TextContains.Count > 0 && !AnyContains(normalizedText, TextContains)) return false;

            return HasAnyCriterion;
        }

        private static void AddValues(DetectionPolicyMatch match, string field, List<string> values, string ruleId, DetectionPolicy policy)
        {
            if (field.Equals("rule_id", StringComparison.OrdinalIgnoreCase)) AddRange(match.RuleIds, values);
            else if (field.Equals("category", StringComparison.OrdinalIgnoreCase)) AddRange(match.Categories, values);
            else if (field.Equals("process_name", StringComparison.OrdinalIgnoreCase)) AddRange(match.ProcessNames, values);
            else if (field.Equals("parent_process", StringComparison.OrdinalIgnoreCase)) AddRange(match.ParentProcesses, values);
            else if (field.Equals("signer", StringComparison.OrdinalIgnoreCase)) AddRange(match.Signers, values);
            else if (field.Equals("path_prefix", StringComparison.OrdinalIgnoreCase)) AddRange(match.PathPrefixes, values);
            else if (field.Equals("command_terms", StringComparison.OrdinalIgnoreCase)) AddRange(match.CommandTerms, values);
            else if (field.Equals("user", StringComparison.OrdinalIgnoreCase)) AddRange(match.Users, values);
            else if (field.Equals("destination_domain", StringComparison.OrdinalIgnoreCase)) AddRange(match.DestinationDomains, values);
            else if (field.Equals("hash", StringComparison.OrdinalIgnoreCase)) AddRange(match.Hashes, values);
            else if (field.Equals("text_contains", StringComparison.OrdinalIgnoreCase)) AddRange(match.TextContains, values);
            else if (field.Equals("ip_cidr", StringComparison.OrdinalIgnoreCase))
            {
                foreach (string value in values)
                {
                    CidrRange range;
                    if (CidrRange.TryParse(value, out range))
                    {
                        match.IpCidrs.Add(value);
                        match.ParsedCidrs.Add(range);
                    }
                    else
                    {
                        policy.Errors.Add("Detection policy entry " + ruleId + " has invalid ip_cidr: " + value);
                    }
                }
            }
            else if (field.Equals("port", StringComparison.OrdinalIgnoreCase))
            {
                foreach (string value in values)
                {
                    int start;
                    int end;
                    if (TryParsePortRange(value, out start, out end))
                    {
                        match.Ports.Add(value);
                    }
                    else
                    {
                        policy.Errors.Add("Detection policy entry " + ruleId + " has invalid port: " + value);
                    }
                }
            }
        }

        private static string CanonicalMatchField(string key)
        {
            string normalized = key == null ? "" : key.Trim().Replace("-", "_").ToLowerInvariant();
            if (normalized.Equals("rule", StringComparison.OrdinalIgnoreCase) ||
                normalized.Equals("rule_id", StringComparison.OrdinalIgnoreCase) ||
                normalized.Equals("rule_ids", StringComparison.OrdinalIgnoreCase))
            {
                return "rule_id";
            }

            if (normalized.Equals("category", StringComparison.OrdinalIgnoreCase) ||
                normalized.Equals("categories", StringComparison.OrdinalIgnoreCase))
            {
                return "category";
            }

            if (normalized.Equals("process", StringComparison.OrdinalIgnoreCase) ||
                normalized.Equals("process_name", StringComparison.OrdinalIgnoreCase) ||
                normalized.Equals("process_names", StringComparison.OrdinalIgnoreCase))
            {
                return "process_name";
            }

            if (normalized.Equals("parent", StringComparison.OrdinalIgnoreCase) ||
                normalized.Equals("parent_process", StringComparison.OrdinalIgnoreCase))
            {
                return "parent_process";
            }

            if (normalized.Equals("signer", StringComparison.OrdinalIgnoreCase)) return "signer";
            if (normalized.Equals("path_prefix", StringComparison.OrdinalIgnoreCase) ||
                normalized.Equals("path_prefixes", StringComparison.OrdinalIgnoreCase))
            {
                return "path_prefix";
            }

            if (normalized.Equals("command_terms", StringComparison.OrdinalIgnoreCase) ||
                normalized.Equals("command_term_group", StringComparison.OrdinalIgnoreCase))
            {
                return "command_terms";
            }

            if (normalized.Equals("user", StringComparison.OrdinalIgnoreCase) ||
                normalized.Equals("account", StringComparison.OrdinalIgnoreCase))
            {
                return "user";
            }

            if (normalized.Equals("destination_domain", StringComparison.OrdinalIgnoreCase) ||
                normalized.Equals("domain", StringComparison.OrdinalIgnoreCase))
            {
                return "destination_domain";
            }

            if (normalized.Equals("ip", StringComparison.OrdinalIgnoreCase) ||
                normalized.Equals("ip_cidr", StringComparison.OrdinalIgnoreCase) ||
                normalized.Equals("cidr", StringComparison.OrdinalIgnoreCase))
            {
                return "ip_cidr";
            }

            if (normalized.Equals("port", StringComparison.OrdinalIgnoreCase) ||
                normalized.Equals("remote_port", StringComparison.OrdinalIgnoreCase))
            {
                return "port";
            }

            if (normalized.Equals("hash", StringComparison.OrdinalIgnoreCase) ||
                normalized.Equals("sha256", StringComparison.OrdinalIgnoreCase))
            {
                return "hash";
            }

            if (normalized.Equals("text_contains", StringComparison.OrdinalIgnoreCase) ||
                normalized.Equals("title_contains", StringComparison.OrdinalIgnoreCase) ||
                normalized.Equals("body_contains", StringComparison.OrdinalIgnoreCase))
            {
                return "text_contains";
            }

            return "";
        }

        private static void AddRange(List<string> target, List<string> values)
        {
            foreach (string value in values)
            {
                if (String.IsNullOrWhiteSpace(value)) continue;
                target.Add(value.Trim());
            }
        }

        private static bool AnyPatternMatches(List<string> patterns, string value)
        {
            foreach (string pattern in patterns)
            {
                if (PatternMatches(pattern, value)) return true;
            }

            return false;
        }

        private static bool PatternMatches(string pattern, string value)
        {
            if (String.IsNullOrWhiteSpace(pattern) || value == null) return false;
            string p = pattern.Trim();
            if (p.Equals("*", StringComparison.Ordinal)) return true;
            if (p.StartsWith("*", StringComparison.Ordinal) && p.EndsWith("*", StringComparison.Ordinal) && p.Length > 2)
            {
                return value.IndexOf(p.Substring(1, p.Length - 2), StringComparison.OrdinalIgnoreCase) >= 0;
            }

            if (p.StartsWith("*", StringComparison.Ordinal) && p.Length > 1)
            {
                return value.EndsWith(p.Substring(1), StringComparison.OrdinalIgnoreCase);
            }

            if (p.EndsWith("*", StringComparison.Ordinal) && p.Length > 1)
            {
                return value.StartsWith(p.Substring(0, p.Length - 1), StringComparison.OrdinalIgnoreCase);
            }

            return value.Equals(p, StringComparison.OrdinalIgnoreCase);
        }

        private static bool AnyContains(string normalizedText, List<string> terms)
        {
            foreach (string term in terms)
            {
                if (!String.IsNullOrWhiteSpace(term) &&
                    normalizedText.IndexOf(Normalize(term), StringComparison.OrdinalIgnoreCase) >= 0)
                {
                    return true;
                }
            }

            return false;
        }

        private static bool AllContains(string normalizedText, List<string> terms)
        {
            foreach (string term in terms)
            {
                if (String.IsNullOrWhiteSpace(term)) continue;
                if (normalizedText.IndexOf(Normalize(term), StringComparison.OrdinalIgnoreCase) < 0)
                {
                    return false;
                }
            }

            return true;
        }

        private static bool AnyPathPrefixMatches(string normalizedText, List<string> prefixes)
        {
            foreach (string prefix in prefixes)
            {
                if (String.IsNullOrWhiteSpace(prefix)) continue;
                if (normalizedText.IndexOf(Normalize(prefix), StringComparison.OrdinalIgnoreCase) >= 0)
                {
                    return true;
                }
            }

            return false;
        }

        private static bool AnyFieldValueMatches(string text, string[] fieldNames, List<string> expectedValues)
        {
            foreach (string fieldName in fieldNames)
            {
                foreach (string expected in expectedValues)
                {
                    if (FieldValueMatches(text, fieldName, expected)) return true;
                }
            }

            return false;
        }

        private static bool FieldValueMatches(string text, string fieldName, string expected)
        {
            if (String.IsNullOrWhiteSpace(text) || String.IsNullOrWhiteSpace(fieldName) || String.IsNullOrWhiteSpace(expected)) return false;

            int index = text.IndexOf(fieldName, StringComparison.OrdinalIgnoreCase);
            while (index >= 0)
            {
                int start = index + fieldName.Length;
                if (ValueMatchesAt(text, start, expected)) return true;
                index = text.IndexOf(fieldName, index + fieldName.Length, StringComparison.OrdinalIgnoreCase);
            }

            return false;
        }

        private static bool ValueMatchesAt(string text, int start, string expected)
        {
            int index = start;
            while (index < text.Length && Char.IsWhiteSpace(text[index]))
            {
                index++;
            }

            if (index < text.Length && text[index] == '"') index++;
            if (index + expected.Length > text.Length) return false;
            if (!text.Substring(index, expected.Length).Equals(expected, StringComparison.OrdinalIgnoreCase)) return false;

            int after = index + expected.Length;
            return after >= text.Length || IsTokenBoundary(text[after]);
        }

        private static bool IsTokenBoundary(char value)
        {
            return Char.IsWhiteSpace(value) ||
                value == '"' ||
                value == '\'' ||
                value == ',' ||
                value == ';' ||
                value == ')' ||
                value == '(' ||
                value == '|' ||
                value == '\r' ||
                value == '\n';
        }

        private static bool AnyCidrMatches(string text, List<CidrRange> ranges)
        {
            foreach (IPAddress address in ExtractIpAddresses(text))
            {
                foreach (CidrRange range in ranges)
                {
                    if (range.Contains(address)) return true;
                }
            }

            return false;
        }

        private static List<IPAddress> ExtractIpAddresses(string text)
        {
            List<IPAddress> result = new List<IPAddress>();
            if (String.IsNullOrWhiteSpace(text)) return result;

            foreach (Match match in Regex.Matches(text, @"\b(?:\d{1,3}\.){3}\d{1,3}\b"))
            {
                IPAddress address;
                if (IPAddress.TryParse(match.Value, out address))
                {
                    result.Add(address);
                }
            }

            return result;
        }

        private static bool AnyPortMatches(string text, List<string> portPatterns)
        {
            List<int> ports = ExtractPorts(text);
            foreach (string pattern in portPatterns)
            {
                int start;
                int end;
                if (!TryParsePortRange(pattern, out start, out end)) continue;
                foreach (int port in ports)
                {
                    if (port >= start && port <= end) return true;
                }
            }

            return false;
        }

        private static List<int> ExtractPorts(string text)
        {
            List<int> result = new List<int>();
            if (String.IsNullOrWhiteSpace(text)) return result;

            foreach (Match match in Regex.Matches(text, @"(?:port=|:)(\d{1,5})\b", RegexOptions.IgnoreCase))
            {
                int port;
                if (Int32.TryParse(match.Groups[1].Value, out port) && port >= 0 && port <= 65535)
                {
                    result.Add(port);
                }
            }

            return result;
        }

        private static bool TryParsePortRange(string value, out int start, out int end)
        {
            start = 0;
            end = 0;
            if (String.IsNullOrWhiteSpace(value)) return false;

            string[] parts = value.Trim().Split('-');
            if (parts.Length == 1)
            {
                if (!Int32.TryParse(parts[0], out start)) return false;
                end = start;
            }
            else if (parts.Length == 2)
            {
                if (!Int32.TryParse(parts[0], out start)) return false;
                if (!Int32.TryParse(parts[1], out end)) return false;
            }
            else
            {
                return false;
            }

            return start >= 0 && end <= 65535 && start <= end;
        }

        private static string AlertText(Alert alert)
        {
            return (alert.RuleId ?? "") + " " +
                (alert.Category ?? "") + " " +
                (alert.Title ?? "") + " " +
                (alert.Body ?? "") + " " +
                (alert.EntitySummary ?? "") + " " +
                (alert.PolicyContext ?? "");
        }

        private static string Normalize(string value)
        {
            if (value == null) return "";
            return value.Replace("\\", "/").Trim();
        }
    }

    internal sealed class DetectionPolicyEngine
    {
        private readonly MonitorConfig config;
        private readonly FileLogger logger;
        private DetectionPolicy policy;
        private DateTime loadedWriteUtc = DateTime.MinValue;

        public DetectionPolicyEngine(MonitorConfig config, FileLogger logger)
        {
            this.config = config;
            this.logger = logger;
        }

        public DetectionPolicyResult Apply(Alert alert)
        {
            DetectionPolicyResult result = new DetectionPolicyResult(alert == null ? 0 : alert.Score);
            if (alert == null || config == null || !config.EnableDetectionPolicy) return result;

            return ApplyPolicy(alert, GetPolicy());
        }

        public DetectionPolicyResult ApplyPolicy(Alert alert, DetectionPolicy current)
        {
            DetectionPolicyResult result = new DetectionPolicyResult(alert == null ? 0 : alert.Score);
            if (alert == null || current == null) return result;

            foreach (DetectionPolicyRule rule in current.Rules)
            {
                if (!rule.Matches(alert)) continue;
                ApplyRule(alert, rule, result);
            }

            result.FinalScore = alert.Score;
            return result;
        }

        public DetectionPolicy PolicyForPreview()
        {
            return GetPolicy();
        }

        private void ApplyRule(Alert alert, DetectionPolicyRule rule, DetectionPolicyResult result)
        {
            int before = alert.Score;
            string action = rule.Action;
            string context = Sanitize(rule.Id) + ":" + action;
            if (!String.IsNullOrWhiteSpace(rule.Tag)) context += ":" + Sanitize(rule.Tag);

            if (action.Equals("lower_score", StringComparison.OrdinalIgnoreCase))
            {
                int score = rule.HasSetScore ? rule.SetScore : before - (rule.HasScoreDelta ? Math.Abs(rule.ScoreDelta) : 10);
                alert.SetScore(score);
            }
            else if (action.Equals("raise_score", StringComparison.OrdinalIgnoreCase))
            {
                int score = rule.HasSetScore ? rule.SetScore : before + (rule.HasScoreDelta ? Math.Abs(rule.ScoreDelta) : 10);
                alert.SetScore(score);
            }
            else if (action.Equals("suppress_external", StringComparison.OrdinalIgnoreCase))
            {
                alert.ExternalSuppressedByPolicy = true;
                result.ExternalSuppressed = true;
            }
            else if (action.Equals("force_alert", StringComparison.OrdinalIgnoreCase))
            {
                alert.ExternalForcedByPolicy = true;
                result.ExternalForced = true;
            }

            alert.AddPolicyContext(context);
            alert.Body = AppendLine(alert.Body, "DetectionPolicy: id=" + Sanitize(rule.Id) +
                " action=" + action +
                " reason=" + Compact(rule.Reason, 160) +
                " score_before=" + before.ToString(CultureInfo.InvariantCulture) +
                " score_after=" + alert.Score.ToString(CultureInfo.InvariantCulture));
            alert.EntitySummary = AppendEntity(alert.EntitySummary, "policy=" + context);
            alert.AddWhy("Detection policy " + rule.Id + " applied action " + action + ": " + Compact(rule.Reason, 160));

            DetectionPolicyAppliedRule applied = new DetectionPolicyAppliedRule();
            applied.Id = rule.Id;
            applied.Action = action;
            applied.Reason = rule.Reason;
            applied.ScoreBefore = before;
            applied.ScoreAfter = alert.Score;
            result.AppliedRules.Add(applied);
            result.FinalScore = alert.Score;
        }

        private DetectionPolicy GetPolicy()
        {
            if (config == null || !config.EnableDetectionPolicy) return new DetectionPolicy();

            try
            {
                DateTime writeUtc = File.Exists(config.DetectionPolicyFile)
                    ? File.GetLastWriteTimeUtc(config.DetectionPolicyFile)
                    : DateTime.MinValue;

                if (policy == null || writeUtc != loadedWriteUtc)
                {
                    DetectionPolicy loaded = DetectionPolicy.Load(config.DetectionPolicyFile);
                    loadedWriteUtc = writeUtc;

                    if (loaded.Errors.Count > 0)
                    {
                        foreach (string error in loaded.Errors)
                        {
                            if (logger != null) logger.Warn(error);
                        }

                        policy = new DetectionPolicy();
                    }
                    else
                    {
                        policy = loaded;
                        if (logger != null)
                        {
                            if (policy.FileFound)
                            {
                                logger.Info("Loaded " + policy.Rules.Count.ToString(CultureInfo.InvariantCulture) +
                                    " detection policy entries from " + config.DetectionPolicyFile + ".");
                            }
                            else
                            {
                                logger.Info("Detection policy file not found; no local policy entries loaded: " + config.DetectionPolicyFile + ".");
                            }

                            foreach (string warning in policy.Warnings)
                            {
                                logger.Warn(warning);
                            }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                if (logger != null) logger.Warn("Detection policy load failed: " + ex.Message);
                policy = new DetectionPolicy();
            }

            return policy ?? new DetectionPolicy();
        }

        private static string AppendLine(string value, string line)
        {
            if (String.IsNullOrWhiteSpace(value)) return line;
            return value + Environment.NewLine + line;
        }

        private static string AppendEntity(string value, string addition)
        {
            if (String.IsNullOrWhiteSpace(value)) return addition;
            return value + " " + addition;
        }

        private static string Sanitize(string value)
        {
            if (String.IsNullOrWhiteSpace(value)) return "unknown";
            return value.Trim()
                .Replace(" ", "_")
                .Replace(",", "_")
                .Replace(";", "_")
                .Replace("|", "_")
                .Replace("\r", "")
                .Replace("\n", "");
        }

        private static string Compact(string value, int maxLength)
        {
            if (String.IsNullOrWhiteSpace(value)) return "not specified";
            string compact = value.Replace("\r", " ").Replace("\n", " ").Trim();
            if (compact.Length <= maxLength) return compact;
            return compact.Substring(0, Math.Max(0, maxLength - 3)) + "...";
        }
    }

    internal sealed class DetectionPolicyResult
    {
        public readonly List<DetectionPolicyAppliedRule> AppliedRules = new List<DetectionPolicyAppliedRule>();
        public int OriginalScore;
        public int FinalScore;
        public bool ExternalSuppressed;
        public bool ExternalForced;

        public DetectionPolicyResult(int originalScore)
        {
            OriginalScore = originalScore;
            FinalScore = originalScore;
        }

        public bool HasMatches
        {
            get { return AppliedRules.Count > 0; }
        }
    }

    internal sealed class DetectionPolicyAppliedRule
    {
        public string Id;
        public string Action;
        public string Reason;
        public int ScoreBefore;
        public int ScoreAfter;
    }
}
