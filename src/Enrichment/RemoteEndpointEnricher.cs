using System;
using System.Collections;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Net;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using System.Web.Script.Serialization;

namespace ArcaneEDR
{
    internal sealed class RemoteEndpointEnricher
    {
        private readonly MonitorConfig config;
        private readonly FileLogger logger;
        private readonly Dictionary<string, CachedRemoteEnrichment> cache = new Dictionary<string, CachedRemoteEnrichment>(StringComparer.OrdinalIgnoreCase);
        private readonly HashSet<string> warned = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        public RemoteEndpointEnricher(MonitorConfig config, FileLogger logger)
        {
            this.config = config;
            this.logger = logger;
        }

        public void Enrich(NetworkSnapshot snapshot)
        {
            if (snapshot == null || !config.EnableRemoteEndpointEnrichment) return;

            Dictionary<string, List<string>> dnsNamesByIp = BuildDnsNamesByIp(snapshot.DnsQueries);
            int rdapLookups = 0;

            foreach (NetworkEndpoint endpoint in snapshot.Endpoints)
            {
                if (endpoint == null || !IpRules.IsExternal(endpoint.RemoteAddress)) continue;

                bool hasLocalDns = ApplyLocalDns(endpoint, dnsNamesByIp);
                RemoteEndpointEnrichment enrichment = Lookup(endpoint.RemoteAddress, ref rdapLookups);
                Apply(endpoint, enrichment);
                FinalizeDomains(endpoint);

                if (hasLocalDns)
                {
                    endpoint.RemoteEnrichmentSource = AppendSource(endpoint.RemoteEnrichmentSource, "local-dns");
                }
            }
        }

        private RemoteEndpointEnrichment Lookup(IPAddress address, ref int rdapLookups)
        {
            if (address == null) return new RemoteEndpointEnrichment();

            string key = address.ToString();
            CachedRemoteEnrichment cached;
            if (cache.TryGetValue(key, out cached) && cached.IsFresh(config.RemoteEndpointEnrichmentCacheMinutes))
            {
                return cached.Enrichment;
            }

            RemoteEndpointEnrichment enrichment = new RemoteEndpointEnrichment();
            enrichment.RemoteIp = key;

            if (config.EnableRemoteEndpointReverseDns)
            {
                enrichment.Rdns = LookupReverseDns(address);
                if (!String.IsNullOrWhiteSpace(enrichment.Rdns))
                {
                    enrichment.Source = AppendSource(enrichment.Source, "rdns");
                }
            }

            if (config.EnableRemoteEndpointRdapEnrichment &&
                rdapLookups < Math.Max(0, config.RemoteEndpointRdapMaxLookupsPerPoll))
            {
                rdapLookups++;
                enrichment.RdapLookupAttempted = true;
                ApplyRdap(address, enrichment);
            }

            cache[key] = new CachedRemoteEnrichment(enrichment);
            return enrichment;
        }

        private bool ApplyLocalDns(NetworkEndpoint endpoint, Dictionary<string, List<string>> dnsNamesByIp)
        {
            if (endpoint == null || endpoint.RemoteAddress == null) return false;

            List<string> names;
            if (!dnsNamesByIp.TryGetValue(endpoint.RemoteAddress.ToString(), out names) || names.Count == 0)
            {
                return false;
            }

            foreach (string name in names)
            {
                AddUnique(endpoint.RemoteDnsNames, name);
            }

            if (String.IsNullOrWhiteSpace(endpoint.RemoteHost))
            {
                endpoint.RemoteHost = names[0];
            }

            return true;
        }

        private void Apply(NetworkEndpoint endpoint, RemoteEndpointEnrichment enrichment)
        {
            if (endpoint == null || enrichment == null) return;

            if (String.IsNullOrWhiteSpace(endpoint.RemoteRdns)) endpoint.RemoteRdns = enrichment.Rdns;
            if (String.IsNullOrWhiteSpace(endpoint.RemoteAsn)) endpoint.RemoteAsn = enrichment.Asn;
            if (String.IsNullOrWhiteSpace(endpoint.RemoteAsnOrg)) endpoint.RemoteAsnOrg = enrichment.AsnOrg;
            if (String.IsNullOrWhiteSpace(endpoint.RemoteOwner)) endpoint.RemoteOwner = enrichment.Owner;
            if (String.IsNullOrWhiteSpace(endpoint.RemoteCountry)) endpoint.RemoteCountry = enrichment.Country;
            if (enrichment.RdapLookupAttempted)
            {
                endpoint.RemoteCountryLookupAttempted = true;
                endpoint.RemoteCountryLookupStatus = String.IsNullOrWhiteSpace(endpoint.RemoteCountry)
                    ? "missing-after-rdap"
                    : "resolved-by-rdap";
            }
            endpoint.RemoteEnrichmentSource = AppendSource(endpoint.RemoteEnrichmentSource, enrichment.Source);
        }

        private static void FinalizeDomains(NetworkEndpoint endpoint)
        {
            if (endpoint == null) return;

            string resolved = FirstNonEmpty(
                endpoint.SniHostname,
                endpoint.ResolvedDomain,
                endpoint.RemoteHost,
                First(endpoint.RemoteDnsNames),
                endpoint.RemoteRdns);

            endpoint.ResolvedDomain = NormalizeDomain(resolved);
            endpoint.RegistrableDomain = RegistrableDomain(endpoint.ResolvedDomain);
        }

        private string LookupReverseDns(IPAddress address)
        {
            try
            {
                Task<IPHostEntry> task = Task.Factory.StartNew(delegate
                {
                    return Dns.GetHostEntry(address);
                });

                if (!task.Wait(TimeoutMilliseconds()))
                {
                    WarnOnce("rdns-timeout", "Remote endpoint reverse DNS lookup timed out; continuing without rDNS enrichment.");
                    return "";
                }

                IPHostEntry entry = task.Result;
                return entry == null ? "" : (entry.HostName ?? "");
            }
            catch (Exception ex)
            {
                WarnOnce("rdns-failed", "Remote endpoint reverse DNS lookup failed; continuing without rDNS enrichment: " + ex.Message);
                return "";
            }
        }

        private void ApplyRdap(IPAddress address, RemoteEndpointEnrichment enrichment)
        {
            if (address == null || enrichment == null) return;
            if (String.IsNullOrWhiteSpace(config.RemoteEndpointRdapUrlTemplate)) return;

            try
            {
                ServicePointManager.SecurityProtocol = ServicePointManager.SecurityProtocol | (SecurityProtocolType)3072;
                string url = config.RemoteEndpointRdapUrlTemplate.Replace("{ip}", Uri.EscapeDataString(address.ToString()));
                HttpWebRequest request = (HttpWebRequest)WebRequest.Create(url);
                request.Method = "GET";
                request.Accept = "application/rdap+json,application/json";
                request.UserAgent = "ArcaneEDR";
                request.Timeout = TimeoutMilliseconds();
                request.ReadWriteTimeout = TimeoutMilliseconds();

                string body;
                using (HttpWebResponse response = (HttpWebResponse)request.GetResponse())
                {
                    body = ReadResponse(response);
                }

                ParseRdap(body, enrichment);
                enrichment.RdapResponseReceived = true;
                enrichment.Source = AppendSource(enrichment.Source, "rdap");
            }
            catch (Exception ex)
            {
                WarnOnce("rdap-failed", "Remote endpoint RDAP enrichment failed; continuing without owner context: " + ex.Message);
            }
        }

        private static void ParseRdap(string body, RemoteEndpointEnrichment enrichment)
        {
            if (String.IsNullOrWhiteSpace(body) || enrichment == null) return;

            JavaScriptSerializer serializer = new JavaScriptSerializer();
            Dictionary<string, object> root = serializer.DeserializeObject(body) as Dictionary<string, object>;
            if (root == null) return;

            string name = ReadString(root, "name");
            string handle = ReadString(root, "handle");
            string country = ReadString(root, "country");
            List<string> entityNames = new List<string>();
            CollectEntityNames(root, entityNames);

            enrichment.Asn = ExtractAsn(root);
            enrichment.AsnOrg = First(entityNames);
            enrichment.Owner = JoinUnique(name, handle, enrichment.AsnOrg);
            enrichment.Country = country;
        }

        private static Dictionary<string, List<string>> BuildDnsNamesByIp(List<DnsQueryEvent> dnsQueries)
        {
            Dictionary<string, List<string>> result = new Dictionary<string, List<string>>(StringComparer.OrdinalIgnoreCase);
            if (dnsQueries == null) return result;

            foreach (DnsQueryEvent dns in dnsQueries)
            {
                if (dns == null || String.IsNullOrWhiteSpace(dns.QueryName) || String.IsNullOrWhiteSpace(dns.QueryResults)) continue;

                foreach (IPAddress address in ExtractIpAddresses(dns.QueryResults))
                {
                    string key = address.ToString();
                    List<string> names;
                    if (!result.TryGetValue(key, out names))
                    {
                        names = new List<string>();
                        result[key] = names;
                    }

                    AddUnique(names, NormalizeDomain(dns.QueryName));
                }
            }

            return result;
        }

        private static List<IPAddress> ExtractIpAddresses(string text)
        {
            List<IPAddress> result = new List<IPAddress>();
            if (String.IsNullOrWhiteSpace(text)) return result;

            MatchCollection matches = Regex.Matches(text, @"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])");
            foreach (Match match in matches)
            {
                IPAddress address;
                if (IPAddress.TryParse(match.Value, out address))
                {
                    AddUnique(result, address);
                }
            }

            string[] tokens = text.Split(new[] { ' ', '\t', '\r', '\n', ';', ',', '[', ']', '(', ')', '"' }, StringSplitOptions.RemoveEmptyEntries);
            foreach (string token in tokens)
            {
                IPAddress address;
                if (IPAddress.TryParse(token.Trim(), out address))
                {
                    AddUnique(result, address);
                }
            }

            return result;
        }

        private static string ExtractAsn(object value)
        {
            List<string> asns = new List<string>();
            CollectAsnNumbers(value, "", asns);
            if (asns.Count > 0) return "AS" + asns[0];

            List<string> strings = new List<string>();
            CollectStrings(value, strings);

            foreach (string item in strings)
            {
                Match match = Regex.Match(item ?? "", @"\bAS\s*(\d{1,10})\b", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
                if (match.Success) return "AS" + match.Groups[1].Value;
            }

            return "";
        }

        private static void CollectAsnNumbers(object value, string keyContext, List<string> asns)
        {
            if (value == null || asns == null) return;

            Dictionary<string, object> map = value as Dictionary<string, object>;
            if (map != null)
            {
                foreach (KeyValuePair<string, object> item in map)
                {
                    CollectAsnNumbers(item.Value, item.Key, asns);
                }

                return;
            }

            object[] array = value as object[];
            if (array != null)
            {
                foreach (object child in array)
                {
                    CollectAsnNumbers(child, keyContext, asns);
                }

                return;
            }

            if (String.IsNullOrWhiteSpace(keyContext)) return;
            string key = keyContext.ToLowerInvariant();
            if (key.IndexOf("asn", StringComparison.OrdinalIgnoreCase) < 0 &&
                key.IndexOf("originautnum", StringComparison.OrdinalIgnoreCase) < 0)
            {
                return;
            }

            string text = value.ToString();
            Match match = Regex.Match(text ?? "", @"\d{1,10}", RegexOptions.CultureInvariant);
            if (match.Success && !Contains(asns, match.Value))
            {
                asns.Add(match.Value);
            }
        }

        private static void CollectEntityNames(object value, List<string> names)
        {
            Dictionary<string, object> map = value as Dictionary<string, object>;
            if (map != null)
            {
                object vcard;
                if (map.TryGetValue("vcardArray", out vcard))
                {
                    CollectVcardNames(vcard, names);
                }

                foreach (object child in map.Values)
                {
                    CollectEntityNames(child, names);
                }

                return;
            }

            object[] array = value as object[];
            if (array == null) return;

            foreach (object child in array)
            {
                CollectEntityNames(child, names);
            }
        }

        private static void CollectVcardNames(object value, List<string> names)
        {
            object[] root = value as object[];
            if (root == null || root.Length < 2) return;

            object[] entries = root[1] as object[];
            if (entries == null) return;

            foreach (object entry in entries)
            {
                object[] fields = entry as object[];
                if (fields == null || fields.Length < 4) continue;

                string fieldName = fields[0] == null ? "" : fields[0].ToString();
                if (!fieldName.Equals("org", StringComparison.OrdinalIgnoreCase) &&
                    !fieldName.Equals("fn", StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }

                string name = VcardValue(fields[3]);
                if (!String.IsNullOrWhiteSpace(name)) AddUnique(names, name);
            }
        }

        private static string VcardValue(object value)
        {
            if (value == null) return "";
            object[] array = value as object[];
            if (array == null) return value.ToString();

            List<string> parts = new List<string>();
            foreach (object item in array)
            {
                string text = VcardValue(item);
                if (!String.IsNullOrWhiteSpace(text)) parts.Add(text);
            }

            return String.Join(" ", parts.ToArray());
        }

        private static void CollectStrings(object value, List<string> strings)
        {
            if (value == null) return;

            string text = value as string;
            if (text != null)
            {
                strings.Add(text);
                return;
            }

            Dictionary<string, object> map = value as Dictionary<string, object>;
            if (map != null)
            {
                foreach (KeyValuePair<string, object> item in map)
                {
                    strings.Add(item.Key);
                    CollectStrings(item.Value, strings);
                }

                return;
            }

            IEnumerable enumerable = value as IEnumerable;
            if (enumerable == null) return;
            foreach (object child in enumerable)
            {
                CollectStrings(child, strings);
            }
        }

        private static string ReadString(Dictionary<string, object> map, string key)
        {
            object value;
            return map != null && map.TryGetValue(key, out value) && value != null ? value.ToString() : "";
        }

        private int TimeoutMilliseconds()
        {
            return Math.Max(1, config.RemoteEndpointEnrichmentTimeoutSeconds) * 1000;
        }

        private void WarnOnce(string key, string message)
        {
            if (logger == null || warned.Contains(key)) return;
            warned.Add(key);
            logger.Warn(message);
        }

        private static string ReadResponse(HttpWebResponse response)
        {
            using (Stream stream = response.GetResponseStream())
            using (StreamReader reader = new StreamReader(stream, Encoding.UTF8))
            {
                return reader.ReadToEnd();
            }
        }

        private static void AddUnique(List<string> values, string value)
        {
            if (values == null || String.IsNullOrWhiteSpace(value)) return;
            string trimmed = value.Trim();
            foreach (string existing in values)
            {
                if (existing.Equals(trimmed, StringComparison.OrdinalIgnoreCase)) return;
            }

            values.Add(trimmed);
        }

        private static void AddUnique(List<IPAddress> values, IPAddress value)
        {
            if (values == null || value == null) return;
            foreach (IPAddress existing in values)
            {
                if (existing.Equals(value)) return;
            }

            values.Add(value);
        }

        private static bool Contains(List<string> values, string value)
        {
            if (values == null || value == null) return false;
            foreach (string existing in values)
            {
                if (existing.Equals(value, StringComparison.OrdinalIgnoreCase)) return true;
            }

            return false;
        }

        private static string JoinUnique(params string[] values)
        {
            List<string> result = new List<string>();
            foreach (string value in values)
            {
                AddUnique(result, value);
            }

            return String.Join("; ", result.ToArray());
        }

        private static string AppendSource(string current, string addition)
        {
            if (String.IsNullOrWhiteSpace(addition)) return current ?? "";
            if (String.IsNullOrWhiteSpace(current)) return addition;

            string[] additions = addition.Split(new[] { ',', ';', ' ' }, StringSplitOptions.RemoveEmptyEntries);
            string result = current;
            foreach (string item in additions)
            {
                if (result.IndexOf(item, StringComparison.OrdinalIgnoreCase) < 0)
                {
                    result += "," + item;
                }
            }

            return result;
        }

        private static string First(List<string> values)
        {
            return values == null || values.Count == 0 ? "" : values[0];
        }

        private static string FirstNonEmpty(params string[] values)
        {
            foreach (string value in values)
            {
                if (!String.IsNullOrWhiteSpace(value)) return value;
            }

            return "";
        }

        private static string NormalizeDomain(string domain)
        {
            if (String.IsNullOrWhiteSpace(domain)) return "";
            string value = domain.Trim().TrimEnd('.').ToLowerInvariant();
            IPAddress ignored;
            return IPAddress.TryParse(value, out ignored) ? "" : value;
        }

        private static string RegistrableDomain(string domain)
        {
            domain = NormalizeDomain(domain);
            if (String.IsNullOrWhiteSpace(domain)) return "";

            string[] labels = domain.Split('.');
            if (labels.Length <= 2) return domain;

            string suffix2 = labels[labels.Length - 2] + "." + labels[labels.Length - 1];
            if (IsTwoLabelPublicSuffix(suffix2) && labels.Length >= 3)
            {
                return labels[labels.Length - 3] + "." + suffix2;
            }

            return suffix2;
        }

        private static bool IsTwoLabelPublicSuffix(string suffix)
        {
            switch (suffix)
            {
                case "co.uk":
                case "org.uk":
                case "ac.uk":
                case "gov.uk":
                case "com.au":
                case "net.au":
                case "org.au":
                case "co.nz":
                case "com.br":
                case "com.mx":
                case "co.jp":
                    return true;
                default:
                    return false;
            }
        }
    }

    internal sealed class RemoteEndpointEnrichment
    {
        public string RemoteIp;
        public string Asn;
        public string AsnOrg;
        public string Rdns;
        public string Owner;
        public string Country;
        public string Source;
        public bool RdapLookupAttempted;
        public bool RdapResponseReceived;
    }

    internal sealed class CachedRemoteEnrichment
    {
        public readonly RemoteEndpointEnrichment Enrichment;
        private readonly DateTime capturedUtc;

        public CachedRemoteEnrichment(RemoteEndpointEnrichment enrichment)
        {
            Enrichment = enrichment ?? new RemoteEndpointEnrichment();
            capturedUtc = DateTime.UtcNow;
        }

        public bool IsFresh(int cacheMinutes)
        {
            if (cacheMinutes <= 0) return false;
            return DateTime.UtcNow - capturedUtc < TimeSpan.FromMinutes(cacheMinutes);
        }
    }
}
