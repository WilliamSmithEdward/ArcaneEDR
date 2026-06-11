using System;
using System.Collections.Generic;

namespace ArcaneEDR
{
    internal sealed class AlertPresentation
    {
        public string Title = "";
        public string RuleId = "";
        public string Category = "";
        public string SourceSummary = "n/a";
        public RemoteEndpointPresentation Remote = new RemoteEndpointPresentation();

        public static AlertPresentation FromAlert(Alert alert)
        {
            AlertPresentation presentation = new AlertPresentation();
            if (alert == null) return presentation;

            presentation.Title = TextFormatting.EmptyIfNull(alert.Title);
            presentation.RuleId = TextFormatting.EmptyIfNull(alert.RuleId);
            presentation.Category = AlertRulePolicy.AlertCategory(alert);
            presentation.SourceSummary = BuildSourceSummary(alert);
            presentation.Remote = BuildRemoteHeaderMetadata(alert);
            return presentation;
        }

        private static string BuildSourceSummary(Alert alert)
        {
            if (alert == null) return "n/a";

            string entity = TextFormatting.EmptyIfNull(alert.EntitySummary);
            List<string> parts = new List<string>();

            string process = AlertEntityTokens.FirstNonEmpty(
                AlertEntityTokens.Get(entity, "process"),
                AlertEntityTokens.FileNameOrValue(AlertEntityTokens.Get(entity, "image")),
                AlertEntityTokens.FileNameOrValue(AlertEntityTokens.Get(entity, "process_path")),
                AlertEntityTokens.FileNameOrValue(AlertEntityTokens.Get(entity, "host_application")));
            AddSummaryPart(parts, "process", process);

            string telemetry = AlertEntityTokens.FirstNonEmpty(
                AlertEntityTokens.Get(entity, "source"),
                InferTelemetrySource(alert));
            AddSummaryPart(parts, "telemetry", telemetry);

            AddSummaryPart(parts, "parent", AlertEntityTokens.Get(entity, "parent"));
            AddSummaryPart(parts, "user", AlertEntityTokens.FirstNonEmpty(AlertEntityTokens.Get(entity, "process_user"), AlertEntityTokens.Get(entity, "user")));
            AddSummaryPart(parts, "local", AlertEntityTokens.Get(entity, "local"));
            AddSummaryPart(parts, "remote", AlertEntityTokens.Get(entity, "remote"));
            AddSummaryPart(parts, "target", TextFormatting.CompactOrEmpty(AlertEntityTokens.Get(entity, "target"), 120));
            AddSummaryPart(parts, "item", TextFormatting.CompactOrEmpty(AlertEntityTokens.FirstNonEmpty(AlertEntityTokens.Get(entity, "name"), AlertEntityTokens.Get(entity, "path")), 120));
            AddSummaryPart(parts, "service", AlertEntityTokens.Get(entity, "service"));

            return parts.Count == 0 ? "n/a" : String.Join("; ", parts.ToArray());
        }

        private static RemoteEndpointPresentation BuildRemoteHeaderMetadata(Alert alert)
        {
            RemoteEndpointPresentation metadata = new RemoteEndpointPresentation();
            if (alert == null) return metadata;

            string entity = TextFormatting.EmptyIfNull(alert.EntitySummary);
            string company = AlertEntityTokens.FirstNonEmpty(
                AlertEntityTokens.Get(entity, "remote_owner"),
                AlertEntityTokens.Get(entity, "owner"),
                AlertEntityTokens.Get(entity, "asn_org"));
            string asn = AlertEntityTokens.Get(entity, "asn");
            string asnOrg = AlertEntityTokens.Get(entity, "asn_org");
            string domain = AlertEntityTokens.FirstNonEmpty(
                AlertEntityTokens.Get(entity, "resolved_domain"),
                AlertEntityTokens.Get(entity, "registrable_domain"),
                AlertEntityTokens.Get(entity, "sni_hostname"),
                AlertEntityTokens.Get(entity, "remote_host"),
                AlertEntityTokens.Get(entity, "rdns"),
                AlertEntityTokens.Get(entity, "dns_names"));
            string lookup = AlertEntityTokens.Get(entity, "country_lookup");
            string enrichmentSource = AlertEntityTokens.Get(entity, "enrichment_source");

            metadata.Endpoint = CleanHeaderValue(
                AlertEntityTokens.FirstNonEmpty(AlertEntityTokens.Get(entity, "remote"), AlertEntityTokens.Get(entity, "remote_ip")),
                120);
            metadata.Country = CleanHeaderValue(AlertEntityTokens.Get(entity, "country"), 80);
            metadata.Company = CleanHeaderValue(company, 180);
            metadata.Asn = CleanHeaderValue(BuildAsnSummary(asn, asnOrg), 180);
            metadata.Domain = CleanHeaderValue(domain, 180);
            metadata.Enrichment = CleanHeaderValue(BuildEnrichmentSummary(enrichmentSource, lookup), 180);
            return metadata;
        }

        private static void AddSummaryPart(List<string> parts, string label, string value)
        {
            if (parts == null || String.IsNullOrWhiteSpace(label) || String.IsNullOrWhiteSpace(value)) return;

            string clean = value.Trim();
            if (!IsMeaningfulHeaderValue(clean)) return;

            parts.Add(label + "=" + clean);
        }

        private static string BuildAsnSummary(string asn, string asnOrg)
        {
            string cleanAsn = CleanHeaderValue(asn, 80);
            string cleanOrg = CleanHeaderValue(asnOrg, 160);

            if (String.IsNullOrWhiteSpace(cleanAsn)) return cleanOrg;
            if (String.IsNullOrWhiteSpace(cleanOrg)) return cleanAsn;
            return cleanAsn + " (" + cleanOrg + ")";
        }

        private static string BuildEnrichmentSummary(string enrichmentSource, string lookup)
        {
            string cleanSource = CleanHeaderValue(enrichmentSource, 120);
            string cleanLookup = CleanHeaderValue(lookup, 120);

            if (String.IsNullOrWhiteSpace(cleanSource)) return cleanLookup;
            if (String.IsNullOrWhiteSpace(cleanLookup)) return cleanSource;
            return cleanSource + " / " + cleanLookup;
        }

        private static string CleanHeaderValue(string value, int maxLength)
        {
            string clean = TextFormatting.CompactOrEmpty(value, maxLength);
            return IsMeaningfulHeaderValue(clean) ? clean : "";
        }

        private static bool IsMeaningfulHeaderValue(string value)
        {
            if (String.IsNullOrWhiteSpace(value)) return false;

            string clean = value.Trim();
            return !clean.Equals("unknown", StringComparison.OrdinalIgnoreCase) &&
                !clean.Equals("n/a", StringComparison.OrdinalIgnoreCase) &&
                !clean.Equals("none", StringComparison.OrdinalIgnoreCase) &&
                !clean.Equals("-", StringComparison.OrdinalIgnoreCase);
        }

        private static string InferTelemetrySource(Alert alert)
        {
            string ruleId = alert == null ? "" : TextFormatting.EmptyIfNull(alert.RuleId);
            string category = alert == null ? "" : AlertRulePolicy.AlertCategory(alert);
            string body = alert == null ? "" : TextFormatting.EmptyIfNull(alert.Body);

            if (AlertRuleTaxonomy.HasPrefix(ruleId, AlertRuleTaxonomy.PrefixNetwork)) return "network";
            if (AlertRuleTaxonomy.HasPrefix(ruleId, AlertRuleTaxonomy.PrefixDns)) return "dns";
            if (AlertRuleTaxonomy.HasPrefix(ruleId, AlertRuleTaxonomy.PrefixPowerShell)) return "powershell";
            if (AlertRuleTaxonomy.HasPrefix(ruleId, AlertRuleTaxonomy.PrefixAuth)) return "windows-event-log";
            if (AlertRuleTaxonomy.HasPrefix(ruleId, AlertRuleTaxonomy.PrefixPersistence)) return "persistence";
            if (AlertRuleTaxonomy.HasPrefix(ruleId, AlertRuleTaxonomy.PrefixFile)) return "sysmon-file";
            if (AlertRuleTaxonomy.HasPrefix(ruleId, AlertRuleTaxonomy.PrefixProcess)) return "process";
            if (AlertRuleTaxonomy.HasAnyPrefix(ruleId, AlertRuleTaxonomy.PrefixService, AlertRuleTaxonomy.PrefixApp)) return "arcane-service";
            if (category.Equals(AlertRuleTaxonomy.CategoryPowerShell, StringComparison.OrdinalIgnoreCase) || body.StartsWith("PowerShell:", StringComparison.OrdinalIgnoreCase)) return "powershell";
            if (category.Equals(AlertRuleTaxonomy.CategoryNetwork, StringComparison.OrdinalIgnoreCase)) return "network";
            if (category.Equals(AlertRuleTaxonomy.CategoryAuth, StringComparison.OrdinalIgnoreCase) || body.StartsWith("WindowsEvent:", StringComparison.OrdinalIgnoreCase)) return "windows-event-log";
            if (category.Equals(AlertRuleTaxonomy.CategoryPersistence, StringComparison.OrdinalIgnoreCase) || body.StartsWith("Persistence:", StringComparison.OrdinalIgnoreCase)) return "persistence";
            if (category.Equals(AlertRuleTaxonomy.CategoryFile, StringComparison.OrdinalIgnoreCase) || body.StartsWith("FileEvent:", StringComparison.OrdinalIgnoreCase)) return "sysmon-file";

            return "";
        }
    }

    internal sealed class RemoteEndpointPresentation
    {
        public string Endpoint = "";
        public string Country = "";
        public string Company = "";
        public string Asn = "";
        public string Domain = "";
        public string Enrichment = "";

        public bool HasAny
        {
            get
            {
                return !String.IsNullOrWhiteSpace(Endpoint) ||
                    !String.IsNullOrWhiteSpace(Country) ||
                    !String.IsNullOrWhiteSpace(Company) ||
                    !String.IsNullOrWhiteSpace(Asn) ||
                    !String.IsNullOrWhiteSpace(Domain) ||
                    !String.IsNullOrWhiteSpace(Enrichment);
            }
        }
    }
}
