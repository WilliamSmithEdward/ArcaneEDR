using System;
using System.Collections;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Net;
using System.Web.Script.Serialization;

namespace ArcaneEDR
{
    internal sealed class RemoteEndpointPolicy
    {
        public readonly List<RemoteEndpointPolicyRule> Rules = new List<RemoteEndpointPolicyRule>();
        public readonly List<string> Warnings = new List<string>();
        public readonly List<string> Errors = new List<string>();
        public string Path;
        public bool FileFound;

        public bool HasCountryCriteria
        {
            get
            {
                foreach (RemoteEndpointPolicyRule rule in Rules)
                {
                    if (rule.Match != null && rule.Match.HasCountryCriteria) return true;
                }

                return false;
            }
        }

        public bool HasOwnerCriteria
        {
            get
            {
                foreach (RemoteEndpointPolicyRule rule in Rules)
                {
                    if (rule.Match != null && rule.Match.HasOwnerCriteria) return true;
                }

                return false;
            }
        }

        public static RemoteEndpointPolicy Load(string path)
        {
            RemoteEndpointPolicy policy = new RemoteEndpointPolicy();
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
                    policy.Errors.Add("Remote endpoint policy file must contain a JSON array or an object with a policies array.");
                    return policy;
                }

                int index = 0;
                foreach (object entry in entries)
                {
                    index++;
                    IDictionary map = entry as IDictionary;
                    if (map == null)
                    {
                        policy.Errors.Add("Remote endpoint policy entry " + index.ToString(CultureInfo.InvariantCulture) + " must be a JSON object.");
                        continue;
                    }

                    RemoteEndpointPolicyRule rule = ParseRule(map, index, policy);
                    if (rule != null)
                    {
                        policy.Rules.Add(rule);
                    }
                }
            }
            catch (Exception ex)
            {
                policy.Errors.Add("Remote endpoint policy file failed to parse: " + ex.Message);
            }

            return policy;
        }

        private static IList EntriesFromRoot(object parsed, RemoteEndpointPolicy policy)
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
                    !key.Equals("remote_endpoint_policies", StringComparison.OrdinalIgnoreCase) &&
                    !key.Equals("remoteEndpointPolicies", StringComparison.OrdinalIgnoreCase) &&
                    !key.Equals("detection_policies", StringComparison.OrdinalIgnoreCase) &&
                    !key.Equals("detectionPolicies", StringComparison.OrdinalIgnoreCase) &&
                    !key.Equals("allowlists", StringComparison.OrdinalIgnoreCase) &&
                    !key.Equals("blocklists", StringComparison.OrdinalIgnoreCase) &&
                    !key.Equals("response_policy", StringComparison.OrdinalIgnoreCase) &&
                    !key.Equals("responsePolicy", StringComparison.OrdinalIgnoreCase) &&
                    !key.Equals("schema", StringComparison.OrdinalIgnoreCase) &&
                    !key.Equals("version", StringComparison.OrdinalIgnoreCase) &&
                    !key.Equals("description", StringComparison.OrdinalIgnoreCase))
                {
                    policy.Warnings.Add("Remote endpoint policy root contains an unknown field: " + key);
                }
            }

            object policies = Value(root, "remote_endpoint_policies");
            if (policies == null) policies = Value(root, "remoteEndpointPolicies");
            if (policies == null) policies = Value(root, "policies");
            if (policies == null) policies = Value(root, "rules");
            return policies as IList;
        }

        private static RemoteEndpointPolicyRule ParseRule(IDictionary map, int index, RemoteEndpointPolicy policy)
        {
            RemoteEndpointPolicyRule rule = new RemoteEndpointPolicyRule();
            rule.Index = index;
            rule.Id = ReadString(map, "id");
            if (String.IsNullOrWhiteSpace(rule.Id))
            {
                rule.Id = "remote-endpoint-policy-" + index.ToString(CultureInfo.InvariantCulture);
                policy.Warnings.Add("Remote endpoint policy entry " + index.ToString(CultureInfo.InvariantCulture) + " is missing id; using " + rule.Id + ".");
            }

            rule.Enabled = ReadBool(map, "enabled", true);
            rule.Action = CanonicalAction(ReadString(map, "action"));
            rule.Reason = ReadString(map, "reason");
            rule.Score = ReadInt(map, "score", 0, out rule.HasScore);

            ValidateTopFields(map, rule, policy);
            ValidateAction(rule, policy);
            if (String.IsNullOrWhiteSpace(rule.Reason))
            {
                policy.Warnings.Add("Remote endpoint policy entry " + rule.Id + " should include a plain-English reason.");
            }

            IDictionary matchMap = Value(map, "match") as IDictionary;
            if (matchMap == null)
            {
                policy.Warnings.Add("Remote endpoint policy entry " + rule.Id + " has no match object and will not match any endpoint.");
                rule.Match = new RemoteEndpointPolicyMatch();
            }
            else
            {
                rule.Match = RemoteEndpointPolicyMatch.Parse(matchMap, rule.Id, policy);
            }

            if (!rule.Match.HasAnyCriterion)
            {
                policy.Warnings.Add("Remote endpoint policy entry " + rule.Id + " has no match criteria and will not match any endpoint.");
            }

            return rule;
        }

        private static void ValidateTopFields(IDictionary map, RemoteEndpointPolicyRule rule, RemoteEndpointPolicy policy)
        {
            foreach (DictionaryEntry entry in map)
            {
                string key = Key(entry.Key);
                if (key.Equals("id", StringComparison.OrdinalIgnoreCase) ||
                    key.Equals("enabled", StringComparison.OrdinalIgnoreCase) ||
                    key.Equals("action", StringComparison.OrdinalIgnoreCase) ||
                    key.Equals("reason", StringComparison.OrdinalIgnoreCase) ||
                    key.Equals("score", StringComparison.OrdinalIgnoreCase) ||
                    key.Equals("match", StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }

                policy.Warnings.Add("Remote endpoint policy entry " + rule.Id + " contains an unknown field: " + key);
            }
        }

        private static void ValidateAction(RemoteEndpointPolicyRule rule, RemoteEndpointPolicy policy)
        {
            if (String.IsNullOrWhiteSpace(rule.Action))
            {
                policy.Errors.Add("Remote endpoint policy entry " + rule.Id + " is missing action.");
                return;
            }

            if (!RemoteEndpointPolicyDecision.IsSupportedAction(rule.Action))
            {
                policy.Errors.Add("Remote endpoint policy entry " + rule.Id + " has unsupported action: " + rule.Action);
            }

            if (rule.HasScore && (rule.Score < 0 || rule.Score > 100))
            {
                policy.Errors.Add("Remote endpoint policy entry " + rule.Id + " score must be between 0 and 100.");
            }
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

            string text = value.ToString().Trim();
            if (text.Length > 0) result.Add(text);
        }

        internal static string Key(object key)
        {
            return key == null ? "" : key.ToString();
        }
    }

    internal sealed class RemoteEndpointPolicyRule
    {
        public int Index;
        public string Id;
        public bool Enabled;
        public string Action;
        public string Reason;
        public bool HasScore;
        public int Score;
        public RemoteEndpointPolicyMatch Match = new RemoteEndpointPolicyMatch();

        public bool Matches(NetworkEndpoint endpoint)
        {
            if (!Enabled || endpoint == null || Match == null) return false;
            return Match.Matches(endpoint);
        }

        public int EffectiveScore
        {
            get
            {
                if (HasScore) return ClampScore(Score);
                if (Action.Equals("block", StringComparison.OrdinalIgnoreCase)) return 95;
                if (Action.Equals("critical", StringComparison.OrdinalIgnoreCase)) return 90;
                if (Action.Equals("observe", StringComparison.OrdinalIgnoreCase)) return 10;
                return 0;
            }
        }

        private static int ClampScore(int score)
        {
            if (score < 0) return 0;
            if (score > 100) return 100;
            return score;
        }
    }

    internal sealed class RemoteEndpointPolicyMatch
    {
        public readonly List<string> ProcessNames = new List<string>();
        public readonly List<string> RemoteIpCidrs = new List<string>();
        public readonly List<CidrRange> ParsedRemoteIpCidrs = new List<CidrRange>();
        public readonly List<string> Ports = new List<string>();
        public readonly List<string> Asns = new List<string>();
        public readonly List<string> AsnOrgs = new List<string>();
        public readonly List<string> Owners = new List<string>();
        public readonly List<string> Domains = new List<string>();
        public readonly List<string> RdnsNames = new List<string>();
        public readonly List<string> DnsNames = new List<string>();
        public readonly List<string> SniHostnames = new List<string>();
        public readonly List<string> ResolvedDomains = new List<string>();
        public readonly List<string> RegistrableDomains = new List<string>();
        public readonly List<string> Countries = new List<string>();
        public readonly List<string> CountryNot = new List<string>();
        public readonly List<string> CountryLookupStatuses = new List<string>();
        public readonly List<string> TextContains = new List<string>();
        public bool HasCountryMissingCriterion;
        public bool CountryMissing;

        public bool HasAnyCriterion
        {
            get { return CriterionCount > 0; }
        }

        public int CriterionCount
        {
            get
            {
                int count = 0;
                if (ProcessNames.Count > 0) count++;
                if (ParsedRemoteIpCidrs.Count > 0) count++;
                if (Ports.Count > 0) count++;
                if (Asns.Count > 0) count++;
                if (AsnOrgs.Count > 0) count++;
                if (Owners.Count > 0) count++;
                if (Domains.Count > 0) count++;
                if (RdnsNames.Count > 0) count++;
                if (DnsNames.Count > 0) count++;
                if (SniHostnames.Count > 0) count++;
                if (ResolvedDomains.Count > 0) count++;
                if (RegistrableDomains.Count > 0) count++;
                if (Countries.Count > 0) count++;
                if (CountryNot.Count > 0) count++;
                if (CountryLookupStatuses.Count > 0) count++;
                if (HasCountryMissingCriterion) count++;
                if (TextContains.Count > 0) count++;
                return count;
            }
        }

        public bool HasCountryCriteria
        {
            get { return Countries.Count > 0 || CountryNot.Count > 0 || CountryLookupStatuses.Count > 0 || HasCountryMissingCriterion; }
        }

        public bool HasOwnerCriteria
        {
            get { return Asns.Count > 0 || AsnOrgs.Count > 0 || Owners.Count > 0; }
        }

        public static RemoteEndpointPolicyMatch Parse(IDictionary map, string ruleId, RemoteEndpointPolicy policy)
        {
            RemoteEndpointPolicyMatch match = new RemoteEndpointPolicyMatch();
            foreach (DictionaryEntry entry in map)
            {
                string key = RemoteEndpointPolicy.Key(entry.Key);
                string canonical = CanonicalMatchField(key);
                if (String.IsNullOrWhiteSpace(canonical))
                {
                    policy.Warnings.Add("Remote endpoint policy entry " + ruleId + " match contains an unknown field: " + key);
                    continue;
                }

                if (canonical.Equals("country_missing", StringComparison.OrdinalIgnoreCase))
                {
                    match.HasCountryMissingCriterion = true;
                    match.CountryMissing = ReadBoolValue(entry.Value, true);
                    continue;
                }

                List<string> values = new List<string>();
                RemoteEndpointPolicy.AddStringValues(values, entry.Value);
                AddValues(match, canonical, values, ruleId, policy);
            }

            return match;
        }

        public bool Matches(NetworkEndpoint endpoint)
        {
            if (endpoint == null) return false;

            if (ProcessNames.Count > 0 && !TextPatternMatcher.IsMatch(endpoint.ProcessName, ProcessNames)) return false;
            if (ParsedRemoteIpCidrs.Count > 0 && !AnyCidrMatches(endpoint.RemoteAddress, ParsedRemoteIpCidrs)) return false;
            if (Ports.Count > 0 && !AnyPortMatches(endpoint.RemotePort, Ports)) return false;
            if (Asns.Count > 0 && !TextPatternMatcher.IsMatch(endpoint.RemoteAsn, Asns)) return false;
            if (AsnOrgs.Count > 0 && !TextPatternMatcher.IsMatch(endpoint.RemoteAsnOrg, AsnOrgs)) return false;
            if (Owners.Count > 0 && !TextPatternMatcher.IsMatch(endpoint.RemoteOwner, Owners)) return false;
            if (Domains.Count > 0 && !TextPatternMatcher.IsMatch(RemoteDomainText(endpoint), Domains)) return false;
            if (RdnsNames.Count > 0 && !TextPatternMatcher.IsMatch(endpoint.RemoteRdns, RdnsNames)) return false;
            if (DnsNames.Count > 0 && !TextPatternMatcher.IsMatch(String.Join(" ", endpoint.RemoteDnsNames.ToArray()), DnsNames)) return false;
            if (SniHostnames.Count > 0 && !TextPatternMatcher.IsMatch(endpoint.SniHostname, SniHostnames)) return false;
            if (ResolvedDomains.Count > 0 && !TextPatternMatcher.IsMatch(endpoint.ResolvedDomain, ResolvedDomains)) return false;
            if (RegistrableDomains.Count > 0 && !TextPatternMatcher.IsMatch(endpoint.RegistrableDomain, RegistrableDomains)) return false;
            if (Countries.Count > 0 && !AnyCountryMatches(endpoint.RemoteCountry, Countries)) return false;
            if (CountryNot.Count > 0 && !CountryNotMatches(endpoint.RemoteCountry, CountryNot)) return false;
            if (CountryLookupStatuses.Count > 0 && !TextPatternMatcher.IsMatch(endpoint.RemoteCountryLookupStatus, CountryLookupStatuses)) return false;
            if (HasCountryMissingCriterion && CountryMissing != IsCountryMissing(endpoint)) return false;
            if (TextContains.Count > 0 && !TextPatternMatcher.IsMatch(RemoteEndpointText(endpoint), TextContains)) return false;

            return HasAnyCriterion;
        }

        private static void AddValues(RemoteEndpointPolicyMatch match, string field, List<string> values, string ruleId, RemoteEndpointPolicy policy)
        {
            if (field.Equals("process_name", StringComparison.OrdinalIgnoreCase)) AddRange(match.ProcessNames, values, false);
            else if (field.Equals("remote_ip", StringComparison.OrdinalIgnoreCase))
            {
                foreach (string value in values)
                {
                    CidrRange range;
                    if (CidrRange.TryParse(value, out range))
                    {
                        match.RemoteIpCidrs.Add(value);
                        match.ParsedRemoteIpCidrs.Add(range);
                    }
                    else
                    {
                        policy.Errors.Add("Remote endpoint policy entry " + ruleId + " has invalid remote_ip CIDR or IP: " + value);
                    }
                }
            }
            else if (field.Equals("port", StringComparison.OrdinalIgnoreCase))
            {
                ValidatePortValues(values, ruleId, policy);
                AddRange(match.Ports, values, false);
            }
            else if (field.Equals("asn", StringComparison.OrdinalIgnoreCase)) AddTextValues(match.Asns, values, ruleId, field, policy);
            else if (field.Equals("asn_org", StringComparison.OrdinalIgnoreCase)) AddTextValues(match.AsnOrgs, values, ruleId, field, policy);
            else if (field.Equals("owner", StringComparison.OrdinalIgnoreCase)) AddTextValues(match.Owners, values, ruleId, field, policy);
            else if (field.Equals("domain", StringComparison.OrdinalIgnoreCase)) AddTextValues(match.Domains, values, ruleId, field, policy);
            else if (field.Equals("rdns", StringComparison.OrdinalIgnoreCase)) AddTextValues(match.RdnsNames, values, ruleId, field, policy);
            else if (field.Equals("dns_name", StringComparison.OrdinalIgnoreCase)) AddTextValues(match.DnsNames, values, ruleId, field, policy);
            else if (field.Equals("sni_hostname", StringComparison.OrdinalIgnoreCase)) AddTextValues(match.SniHostnames, values, ruleId, field, policy);
            else if (field.Equals("resolved_domain", StringComparison.OrdinalIgnoreCase)) AddTextValues(match.ResolvedDomains, values, ruleId, field, policy);
            else if (field.Equals("registrable_domain", StringComparison.OrdinalIgnoreCase)) AddTextValues(match.RegistrableDomains, values, ruleId, field, policy);
            else if (field.Equals("country", StringComparison.OrdinalIgnoreCase)) AddRange(match.Countries, values, true);
            else if (field.Equals("country_not", StringComparison.OrdinalIgnoreCase)) AddRange(match.CountryNot, values, true);
            else if (field.Equals("country_lookup", StringComparison.OrdinalIgnoreCase)) AddTextValues(match.CountryLookupStatuses, values, ruleId, field, policy);
            else if (field.Equals("text_contains", StringComparison.OrdinalIgnoreCase)) AddTextValues(match.TextContains, values, ruleId, field, policy);
        }

        private static void AddTextValues(List<string> target, List<string> values, string ruleId, string field, RemoteEndpointPolicy policy)
        {
            foreach (string value in values)
            {
                string message;
                if (!TextPatternMatcher.TryValidateRegexEntry(value, out message))
                {
                    policy.Errors.Add("Remote endpoint policy entry " + ruleId + " has invalid regex in " + field + ": " + message);
                }
            }

            AddRange(target, values, false);
        }

        private static void ValidatePortValues(List<string> values, string ruleId, RemoteEndpointPolicy policy)
        {
            foreach (string value in values)
            {
                int start;
                int end;
                if (!TryParsePortRange(value, out start, out end))
                {
                    policy.Errors.Add("Remote endpoint policy entry " + ruleId + " has invalid port or port range: " + value);
                }
            }
        }

        private static string CanonicalMatchField(string key)
        {
            string normalized = key == null ? "" : key.Trim().Replace("-", "_").ToLowerInvariant();
            if (normalized.Equals("process_name", StringComparison.OrdinalIgnoreCase)) return "process_name";
            if (normalized.Equals("remote_ip", StringComparison.OrdinalIgnoreCase)) return "remote_ip";
            if (normalized.Equals("port", StringComparison.OrdinalIgnoreCase)) return "port";
            if (normalized.Equals("asn", StringComparison.OrdinalIgnoreCase)) return "asn";
            if (normalized.Equals("asn_org", StringComparison.OrdinalIgnoreCase)) return "asn_org";
            if (normalized.Equals("owner", StringComparison.OrdinalIgnoreCase)) return "owner";
            if (normalized.Equals("domain", StringComparison.OrdinalIgnoreCase)) return "domain";
            if (normalized.Equals("rdns", StringComparison.OrdinalIgnoreCase)) return "rdns";
            if (normalized.Equals("dns_name", StringComparison.OrdinalIgnoreCase)) return "dns_name";
            if (normalized.Equals("sni_hostname", StringComparison.OrdinalIgnoreCase)) return "sni_hostname";
            if (normalized.Equals("resolved_domain", StringComparison.OrdinalIgnoreCase)) return "resolved_domain";
            if (normalized.Equals("registrable_domain", StringComparison.OrdinalIgnoreCase)) return "registrable_domain";
            if (normalized.Equals("country", StringComparison.OrdinalIgnoreCase)) return "country";
            if (normalized.Equals("country_not", StringComparison.OrdinalIgnoreCase)) return "country_not";
            if (normalized.Equals("country_lookup", StringComparison.OrdinalIgnoreCase)) return "country_lookup";
            if (normalized.Equals("country_missing", StringComparison.OrdinalIgnoreCase)) return "country_missing";
            if (normalized.Equals("text_contains", StringComparison.OrdinalIgnoreCase)) return "text_contains";
            return "";
        }

        private static void AddRange(List<string> target, List<string> values, bool normalizeCountry)
        {
            foreach (string value in values)
            {
                if (String.IsNullOrWhiteSpace(value)) continue;
                string normalized = normalizeCountry ? NormalizeCountry(value) : value.Trim();
                if (normalized.Length > 0) target.Add(normalized);
            }
        }

        private static bool AnyCidrMatches(IPAddress address, List<CidrRange> ranges)
        {
            if (address == null) return false;
            foreach (CidrRange range in ranges)
            {
                if (range.Contains(address)) return true;
            }

            return false;
        }

        private static bool AnyPortMatches(int port, List<string> portPatterns)
        {
            foreach (string pattern in portPatterns)
            {
                int start;
                int end;
                if (!TryParsePortRange(pattern, out start, out end)) continue;
                if (port >= start && port <= end) return true;
            }

            return false;
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

        private static bool AnyCountryMatches(string country, List<string> expected)
        {
            string normalized = NormalizeCountry(country);
            if (normalized.Length == 0) return false;
            foreach (string value in expected)
            {
                if (normalized.Equals(value, StringComparison.OrdinalIgnoreCase)) return true;
            }

            return false;
        }

        private static bool CountryNotMatches(string country, List<string> deniedAllowedSet)
        {
            string normalized = NormalizeCountry(country);
            if (normalized.Length == 0) return false;

            foreach (string value in deniedAllowedSet)
            {
                if (normalized.Equals(value, StringComparison.OrdinalIgnoreCase)) return false;
            }

            return true;
        }

        private static bool IsCountryMissing(NetworkEndpoint endpoint)
        {
            return endpoint != null &&
                endpoint.RemoteCountryLookupAttempted &&
                String.IsNullOrWhiteSpace(endpoint.RemoteCountry);
        }

        private static string NormalizeCountry(string value)
        {
            if (String.IsNullOrWhiteSpace(value)) return "";

            string trimmed = value.Trim();
            if (trimmed.Equals("USA", StringComparison.OrdinalIgnoreCase) ||
                trimmed.Equals("United States", StringComparison.OrdinalIgnoreCase) ||
                trimmed.Equals("United States of America", StringComparison.OrdinalIgnoreCase))
            {
                return "US";
            }

            return trimmed.ToUpperInvariant();
        }

        private static bool ReadBoolValue(object value, bool fallback)
        {
            if (value == null) return fallback;
            if (value is bool) return (bool)value;

            bool parsed;
            return Boolean.TryParse(value.ToString(), out parsed) ? parsed : fallback;
        }

        private static string RemoteDomainText(NetworkEndpoint endpoint)
        {
            if (endpoint == null) return "";
            return (endpoint.RemoteHost ?? "") + " " +
                (endpoint.RemoteRdns ?? "") + " " +
                String.Join(" ", endpoint.RemoteDnsNames.ToArray()) + " " +
                (endpoint.SniHostname ?? "") + " " +
                (endpoint.ResolvedDomain ?? "") + " " +
                (endpoint.RegistrableDomain ?? "");
        }

        private static string RemoteEndpointText(NetworkEndpoint endpoint)
        {
            if (endpoint == null) return "";
            return endpoint.EntitySummary + " " + endpoint.RemoteContextText();
        }
    }

    internal sealed class RemoteEndpointPolicyDecision
    {
        public static readonly RemoteEndpointPolicyDecision None = new RemoteEndpointPolicyDecision();

        public bool Matched;
        public string RuleId = "";
        public string Action = "";
        public string Reason = "";
        public int Score;

        public bool IsAllow
        {
            get { return Action.Equals("allow", StringComparison.OrdinalIgnoreCase); }
        }

        public bool IsTrust
        {
            get { return Action.Equals("trust", StringComparison.OrdinalIgnoreCase); }
        }

        public bool IsBlock
        {
            get { return Action.Equals("block", StringComparison.OrdinalIgnoreCase); }
        }

        public bool IsCritical
        {
            get { return Action.Equals("critical", StringComparison.OrdinalIgnoreCase); }
        }

        public bool IsObserve
        {
            get { return Action.Equals("observe", StringComparison.OrdinalIgnoreCase); }
        }

        public bool IsHighSignal
        {
            get { return IsBlock || IsCritical; }
        }

        public static bool IsSupportedAction(string action)
        {
            return action.Equals("allow", StringComparison.OrdinalIgnoreCase) ||
                action.Equals("trust", StringComparison.OrdinalIgnoreCase) ||
                action.Equals("block", StringComparison.OrdinalIgnoreCase) ||
                action.Equals("critical", StringComparison.OrdinalIgnoreCase) ||
                action.Equals("observe", StringComparison.OrdinalIgnoreCase);
        }

        public static RemoteEndpointPolicyDecision FromRule(RemoteEndpointPolicyRule rule)
        {
            if (rule == null) return None;

            RemoteEndpointPolicyDecision decision = new RemoteEndpointPolicyDecision();
            decision.Matched = true;
            decision.RuleId = rule.Id ?? "";
            decision.Action = rule.Action ?? "";
            decision.Reason = rule.Reason ?? "";
            decision.Score = rule.EffectiveScore;
            return decision;
        }
    }

    internal sealed class RemoteEndpointPolicyEngine
    {
        private readonly MonitorConfig config;
        private readonly FileLogger logger;
        private RemoteEndpointPolicy policy;
        private DateTime loadedWriteUtc = DateTime.MinValue;

        public RemoteEndpointPolicyEngine(MonitorConfig config, FileLogger logger)
        {
            this.config = config;
            this.logger = logger;
        }

        public RemoteEndpointPolicyDecision Evaluate(NetworkEndpoint endpoint)
        {
            if (endpoint == null || config == null || !config.EnableRemoteEndpointPolicy) return RemoteEndpointPolicyDecision.None;

            RemoteEndpointPolicy current = GetPolicy();
            foreach (RemoteEndpointPolicyRule rule in current.Rules)
            {
                if (!rule.Matches(endpoint)) continue;
                return RemoteEndpointPolicyDecision.FromRule(rule);
            }

            return RemoteEndpointPolicyDecision.None;
        }

        public RemoteEndpointPolicy PolicyForPreview()
        {
            return GetPolicy();
        }

        private RemoteEndpointPolicy GetPolicy()
        {
            if (config == null || !config.EnableRemoteEndpointPolicy) return new RemoteEndpointPolicy();

            try
            {
                DateTime writeUtc = File.Exists(config.RemoteEndpointPolicyFile)
                    ? File.GetLastWriteTimeUtc(config.RemoteEndpointPolicyFile)
                    : DateTime.MinValue;

                if (policy == null || writeUtc != loadedWriteUtc)
                {
                    RemoteEndpointPolicy loaded = RemoteEndpointPolicy.Load(config.RemoteEndpointPolicyFile);
                    loadedWriteUtc = writeUtc;

                    if (loaded.Errors.Count > 0)
                    {
                        foreach (string error in loaded.Errors)
                        {
                            if (logger != null) logger.Warn(error);
                        }

                        policy = new RemoteEndpointPolicy();
                    }
                    else
                    {
                        policy = loaded;
                        if (logger != null)
                        {
                            if (policy.FileFound)
                            {
                                logger.Info("Loaded " + policy.Rules.Count.ToString(CultureInfo.InvariantCulture) +
                                    " remote endpoint policy entries from " + config.RemoteEndpointPolicyFile + ".");
                            }
                            else
                            {
                                logger.Warn("Remote endpoint policy file not found: " + config.RemoteEndpointPolicyFile + ".");
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
                if (logger != null) logger.Warn("Remote endpoint policy load failed: " + ex.Message);
                policy = new RemoteEndpointPolicy();
            }

            return policy ?? new RemoteEndpointPolicy();
        }
    }
}
