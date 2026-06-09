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
        private CountryBlockDatabase countryBlockDatabase;

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
            int geoProviderLookups = 0;

            foreach (NetworkEndpoint endpoint in snapshot.Endpoints)
            {
                if (endpoint == null || !IpRules.IsExternal(endpoint.RemoteAddress)) continue;

                bool hasLocalDns = ApplyLocalDns(endpoint, dnsNamesByIp);
                RemoteEndpointEnrichment enrichment = Lookup(endpoint.RemoteAddress, ref rdapLookups, ref geoProviderLookups);
                Apply(endpoint, enrichment);
                if (hasLocalDns)
                {
                    endpoint.RemoteEnrichmentSource = AppendSource(endpoint.RemoteEnrichmentSource, "local-dns");
                }

                FinalizeDomains(endpoint);
                FinalizeCountryLookupStatus(endpoint, enrichment);
            }
        }

        private RemoteEndpointEnrichment Lookup(IPAddress address, ref int rdapLookups, ref int geoProviderLookups)
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

            if (config.EnableRemoteEndpointCountryBlockEnrichment)
            {
                enrichment.CountryBlockLookupAttempted = true;
                string country = LookupCountryBlock(address);
                if (!String.IsNullOrWhiteSpace(country))
                {
                    enrichment.Country = NormalizeCountryCode(country);
                    enrichment.CountrySource = "country-blocks";
                    enrichment.CountryBlockLookupMatched = true;
                    enrichment.Source = AppendSource(enrichment.Source, "country-blocks");
                }
            }

            if (config.EnableRemoteEndpointRdapEnrichment &&
                rdapLookups < Math.Max(0, config.RemoteEndpointRdapMaxLookupsPerPoll))
            {
                rdapLookups++;
                enrichment.RdapLookupAttempted = true;
                ApplyRdap(address, enrichment);
            }

            if (NeedsGeoProviderEnrichment(enrichment) &&
                config.EnableRemoteEndpointIpApiGeolocation)
            {
                if (CanUseGeoProviderLookup(geoProviderLookups))
                {
                    geoProviderLookups++;
                    enrichment.IpApiLookupAttempted = true;
                    ApplyIpApi(address, enrichment);
                }
                else
                {
                    enrichment.GeoProviderLookupDeferred = true;
                }
            }

            if (NeedsGeoProviderEnrichment(enrichment) &&
                config.EnableRemoteEndpointIpWhoisGeolocation)
            {
                if (CanUseGeoProviderLookup(geoProviderLookups))
                {
                    geoProviderLookups++;
                    enrichment.IpWhoisLookupAttempted = true;
                    ApplyIpWhois(address, enrichment);
                }
                else
                {
                    enrichment.GeoProviderLookupDeferred = true;
                }
            }

            if (!enrichment.GeoProviderLookupDeferred)
            {
                cache[key] = new CachedRemoteEnrichment(enrichment);
            }

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
            if (enrichment.RdapLookupAttempted ||
                enrichment.CountryBlockLookupAttempted ||
                enrichment.IpApiLookupAttempted ||
                enrichment.IpWhoisLookupAttempted)
            {
                endpoint.RemoteCountryLookupAttempted = true;
            }
            endpoint.RemoteEnrichmentSource = AppendSource(endpoint.RemoteEnrichmentSource, enrichment.Source);
        }

        private void FinalizeCountryLookupStatus(NetworkEndpoint endpoint, RemoteEndpointEnrichment enrichment)
        {
            if (endpoint == null || enrichment == null) return;

            if (!String.IsNullOrWhiteSpace(endpoint.RemoteCountry))
            {
                if (!String.IsNullOrWhiteSpace(enrichment.CountrySource))
                {
                    endpoint.RemoteCountryLookupStatus = "resolved-by-" + enrichment.CountrySource;
                }
                else if (enrichment.CountryBlockLookupMatched)
                {
                    endpoint.RemoteCountryLookupStatus = "resolved-by-country-blocks";
                }
                else if (enrichment.IpApiLookupMatched)
                {
                    endpoint.RemoteCountryLookupStatus = "resolved-by-ip-api";
                }
                else if (enrichment.IpWhoisLookupMatched)
                {
                    endpoint.RemoteCountryLookupStatus = "resolved-by-ipwhois";
                }
                else if (enrichment.RdapLookupAttempted)
                {
                    endpoint.RemoteCountryLookupStatus = "resolved-by-rdap";
                }

                return;
            }

            List<string> sources = new List<string>();
            if (enrichment.CountryBlockLookupAttempted) sources.Add("country-blocks");
            if (enrichment.IpApiLookupAttempted) sources.Add("ip-api");
            if (enrichment.IpWhoisLookupAttempted) sources.Add("ipwhois");
            if (enrichment.RdapLookupAttempted) sources.Add("rdap");

            if (sources.Count == 0)
            {
                return;
            }

            bool domainMissing = !HasDomainIdentity(endpoint);
            if (domainMissing) sources.Add("dns");

            string prefix = enrichment.GeoProviderLookupDeferred ? "deferred-after-" : "missing-after-";
            endpoint.RemoteCountryLookupStatus = prefix + String.Join("-", sources.ToArray());
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

        private static bool HasDomainIdentity(NetworkEndpoint endpoint)
        {
            return endpoint != null &&
                (!String.IsNullOrWhiteSpace(endpoint.SniHostname) ||
                    !String.IsNullOrWhiteSpace(endpoint.ResolvedDomain) ||
                    !String.IsNullOrWhiteSpace(endpoint.RemoteHost) ||
                    !String.IsNullOrWhiteSpace(endpoint.RemoteRdns) ||
                    (endpoint.RemoteDnsNames != null && endpoint.RemoteDnsNames.Count > 0));
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

        private bool CanUseGeoProviderLookup(int geoProviderLookups)
        {
            return geoProviderLookups < Math.Max(0, config.RemoteEndpointGeoProviderMaxLookupsPerPoll);
        }

        private static bool NeedsGeoProviderEnrichment(RemoteEndpointEnrichment enrichment)
        {
            if (enrichment == null) return false;

            if (String.IsNullOrWhiteSpace(enrichment.Country)) return true;
            if (String.IsNullOrWhiteSpace(enrichment.Owner)) return true;
            return String.IsNullOrWhiteSpace(enrichment.Asn) &&
                String.IsNullOrWhiteSpace(enrichment.AsnOrg);
        }

        private void ApplyIpApi(IPAddress address, RemoteEndpointEnrichment enrichment)
        {
            if (address == null || enrichment == null) return;
            if (String.IsNullOrWhiteSpace(config.RemoteEndpointIpApiUrlTemplate)) return;

            try
            {
                string body = ReadHttpBody(config.RemoteEndpointIpApiUrlTemplate, address, "application/json");
                ParseIpApi(body, enrichment);
                enrichment.IpApiResponseReceived = true;
                enrichment.Source = AppendSource(enrichment.Source, "ip-api");
            }
            catch (Exception ex)
            {
                WarnOnce("ip-api-failed", "Remote endpoint ip-api.com geolocation failed; continuing without that provider context: " + ex.Message);
            }
        }

        private void ApplyIpWhois(IPAddress address, RemoteEndpointEnrichment enrichment)
        {
            if (address == null || enrichment == null) return;
            if (String.IsNullOrWhiteSpace(config.RemoteEndpointIpWhoisUrlTemplate)) return;

            try
            {
                string body = ReadHttpBody(config.RemoteEndpointIpWhoisUrlTemplate, address, "application/json");
                ParseIpWhois(body, enrichment);
                enrichment.IpWhoisResponseReceived = true;
                enrichment.Source = AppendSource(enrichment.Source, "ipwhois");
            }
            catch (Exception ex)
            {
                WarnOnce("ipwhois-failed", "Remote endpoint ipwhois.io geolocation failed; continuing without that provider context: " + ex.Message);
            }
        }

        private void ApplyRdap(IPAddress address, RemoteEndpointEnrichment enrichment)
        {
            if (address == null || enrichment == null) return;
            if (String.IsNullOrWhiteSpace(config.RemoteEndpointRdapUrlTemplate)) return;

            try
            {
                string body = ReadHttpBody(config.RemoteEndpointRdapUrlTemplate, address, "application/rdap+json,application/json");
                ParseRdap(body, enrichment);
                enrichment.RdapResponseReceived = true;
                enrichment.Source = AppendSource(enrichment.Source, "rdap");
            }
            catch (Exception ex)
            {
                WarnOnce("rdap-failed", "Remote endpoint RDAP enrichment failed; continuing without owner context: " + ex.Message);
            }
        }

        private string ReadHttpBody(string urlTemplate, IPAddress address, string accept)
        {
            ServicePointManager.SecurityProtocol = ServicePointManager.SecurityProtocol | (SecurityProtocolType)3072;
            string url = urlTemplate.Replace("{ip}", Uri.EscapeDataString(address.ToString()));
            HttpWebRequest request = (HttpWebRequest)WebRequest.Create(url);
            request.Method = "GET";
            request.Accept = accept;
            request.UserAgent = "ArcaneEDR";
            request.Timeout = TimeoutMilliseconds();
            request.ReadWriteTimeout = TimeoutMilliseconds();

            using (HttpWebResponse response = (HttpWebResponse)request.GetResponse())
            {
                return ReadResponse(response);
            }
        }

        private static void ParseIpApi(string body, RemoteEndpointEnrichment enrichment)
        {
            if (String.IsNullOrWhiteSpace(body) || enrichment == null) return;

            JavaScriptSerializer serializer = new JavaScriptSerializer();
            Dictionary<string, object> root = serializer.DeserializeObject(body) as Dictionary<string, object>;
            if (root == null) return;

            if (!ReadString(root, "status").Equals("success", StringComparison.OrdinalIgnoreCase))
            {
                return;
            }

            string country = NormalizeCountryCode(ReadString(root, "countryCode"));
            if (!String.IsNullOrWhiteSpace(country) && String.IsNullOrWhiteSpace(enrichment.Country))
            {
                enrichment.Country = country;
                enrichment.CountrySource = "ip-api";
                enrichment.IpApiLookupMatched = true;
            }

            string asn = NormalizeAsn(ReadString(root, "as"));
            string asnOrg = FirstNonEmpty(ReadString(root, "asname"), ReadString(root, "org"), ReadString(root, "isp"));
            string owner = JoinUnique(ReadString(root, "org"), ReadString(root, "isp"), asnOrg);
            ApplyProviderIdentity(enrichment, asn, asnOrg, owner);
        }

        private static void ParseIpWhois(string body, RemoteEndpointEnrichment enrichment)
        {
            if (String.IsNullOrWhiteSpace(body) || enrichment == null) return;

            JavaScriptSerializer serializer = new JavaScriptSerializer();
            Dictionary<string, object> root = serializer.DeserializeObject(body) as Dictionary<string, object>;
            if (root == null) return;

            if (!ReadBool(root, "success"))
            {
                return;
            }

            string country = NormalizeCountryCode(ReadString(root, "country_code"));
            if (!String.IsNullOrWhiteSpace(country) && String.IsNullOrWhiteSpace(enrichment.Country))
            {
                enrichment.Country = country;
                enrichment.CountrySource = "ipwhois";
                enrichment.IpWhoisLookupMatched = true;
            }

            string asn = NormalizeAsn(ReadString(root, "asn"));
            string asnOrg = FirstNonEmpty(ReadString(root, "org"), ReadString(root, "isp"));
            string owner = JoinUnique(ReadString(root, "org"), ReadString(root, "isp"));
            ApplyProviderIdentity(enrichment, asn, asnOrg, owner);
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

            string asn = ExtractAsn(root);
            string asnOrg = First(entityNames);
            if (String.IsNullOrWhiteSpace(enrichment.Asn)) enrichment.Asn = asn;
            if (String.IsNullOrWhiteSpace(enrichment.AsnOrg)) enrichment.AsnOrg = asnOrg;
            enrichment.Owner = JoinUnique(enrichment.Owner, name, handle, asnOrg);
            if (String.IsNullOrWhiteSpace(enrichment.Country))
            {
                enrichment.Country = NormalizeCountryCode(country);
                if (!String.IsNullOrWhiteSpace(enrichment.Country))
                {
                    enrichment.CountrySource = "rdap";
                }
            }
        }

        private string LookupCountryBlock(IPAddress address)
        {
            if (address == null) return "";

            CountryBlockDatabase database = GetCountryBlockDatabase();
            return database == null ? "" : database.Lookup(address);
        }

        private CountryBlockDatabase GetCountryBlockDatabase()
        {
            if (countryBlockDatabase != null) return countryBlockDatabase;

            if (String.IsNullOrWhiteSpace(config.RemoteEndpointCountryBlocksDirectory))
            {
                return null;
            }

            if (!Directory.Exists(config.RemoteEndpointCountryBlocksDirectory))
            {
                WarnOnce("country-blocks-missing", "Remote endpoint country block directory not found; continuing without local country enrichment: " + config.RemoteEndpointCountryBlocksDirectory);
                countryBlockDatabase = new CountryBlockDatabase();
                return countryBlockDatabase;
            }

            countryBlockDatabase = CountryBlockDatabase.Load(config.RemoteEndpointCountryBlocksDirectory, logger);
            return countryBlockDatabase;
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

        private static bool ReadBool(Dictionary<string, object> map, string key)
        {
            object value;
            if (map == null || !map.TryGetValue(key, out value) || value == null) return false;

            if (value is bool) return (bool)value;

            string text = value.ToString();
            bool parsed;
            if (Boolean.TryParse(text, out parsed)) return parsed;

            return text.Equals("1", StringComparison.OrdinalIgnoreCase) ||
                text.Equals("yes", StringComparison.OrdinalIgnoreCase) ||
                text.Equals("success", StringComparison.OrdinalIgnoreCase);
        }

        private static void ApplyProviderIdentity(RemoteEndpointEnrichment enrichment, string asn, string asnOrg, string owner)
        {
            if (enrichment == null) return;

            if (String.IsNullOrWhiteSpace(enrichment.Asn)) enrichment.Asn = NormalizeAsn(asn);
            if (String.IsNullOrWhiteSpace(enrichment.AsnOrg)) enrichment.AsnOrg = asnOrg;
            enrichment.Owner = JoinUnique(enrichment.Owner, owner, asnOrg);
        }

        private static string NormalizeCountryCode(string value)
        {
            if (String.IsNullOrWhiteSpace(value)) return "";

            string trimmed = value.Trim();
            return trimmed.Length == 2 ? trimmed.ToUpperInvariant() : trimmed;
        }

        private static string NormalizeAsn(string value)
        {
            if (String.IsNullOrWhiteSpace(value)) return "";

            Match match = Regex.Match(value, @"\bAS\s*(\d{1,10})\b", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
            if (match.Success) return "AS" + match.Groups[1].Value;

            match = Regex.Match(value, @"\b(\d{1,10})\b", RegexOptions.CultureInvariant);
            return match.Success ? "AS" + match.Groups[1].Value : "";
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
        public string CountrySource;
        public string Source;
        public bool CountryBlockLookupAttempted;
        public bool CountryBlockLookupMatched;
        public bool IpApiLookupAttempted;
        public bool IpApiLookupMatched;
        public bool IpApiResponseReceived;
        public bool IpWhoisLookupAttempted;
        public bool IpWhoisLookupMatched;
        public bool IpWhoisResponseReceived;
        public bool GeoProviderLookupDeferred;
        public bool RdapLookupAttempted;
        public bool RdapResponseReceived;
    }

    internal sealed class CountryBlockDatabase
    {
        private readonly List<CountryBlockRange> ranges = new List<CountryBlockRange>();

        public static CountryBlockDatabase Load(string directory, FileLogger logger)
        {
            CountryBlockDatabase database = new CountryBlockDatabase();
            if (String.IsNullOrWhiteSpace(directory) || !Directory.Exists(directory)) return database;

            foreach (string path in Directory.GetFiles(directory, "*.txt", SearchOption.AllDirectories))
            {
                string countryCode = CountryCodeFromPath(path);
                if (String.IsNullOrWhiteSpace(countryCode)) continue;

                foreach (string line in File.ReadAllLines(path))
                {
                    string value = CleanLine(line);
                    if (String.IsNullOrWhiteSpace(value)) continue;

                    CidrRange range;
                    if (CidrRange.TryParse(value, out range))
                    {
                        database.ranges.Add(new CountryBlockRange(range, countryCode));
                    }
                }
            }

            if (logger != null)
            {
                logger.Info("Loaded " + database.ranges.Count.ToString(CultureInfo.InvariantCulture) +
                    " remote endpoint country block ranges from " + directory + ".");
            }

            return database;
        }

        public string Lookup(IPAddress address)
        {
            if (address == null) return "";

            foreach (CountryBlockRange range in ranges)
            {
                if (range.Range.Contains(address)) return range.CountryCode;
            }

            return "";
        }

        private static string CountryCodeFromPath(string path)
        {
            if (String.IsNullOrWhiteSpace(path)) return "";

            DirectoryInfo parent = Directory.GetParent(path);
            string value = parent == null ? "" : parent.Name;
            if (!IsCountryCode(value))
            {
                value = Path.GetFileNameWithoutExtension(path);
                if (value != null && value.Length > 2) value = value.Substring(0, 2);
            }

            return IsCountryCode(value) ? value.ToUpperInvariant() : "";
        }

        private static bool IsCountryCode(string value)
        {
            if (String.IsNullOrWhiteSpace(value) || value.Length != 2) return false;
            return Char.IsLetter(value[0]) && Char.IsLetter(value[1]);
        }

        private static string CleanLine(string line)
        {
            if (String.IsNullOrWhiteSpace(line)) return "";

            string value = line.Trim();
            int comment = value.IndexOf('#');
            if (comment >= 0) value = value.Substring(0, comment).Trim();
            return value;
        }
    }

    internal sealed class CountryBlockRange
    {
        public readonly CidrRange Range;
        public readonly string CountryCode;

        public CountryBlockRange(CidrRange range, string countryCode)
        {
            Range = range;
            CountryCode = countryCode ?? "";
        }
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
