using System;

namespace ArcaneEDR
{
    internal static class AlertReasonAnnotator
    {
        public static Alert Annotate(Alert alert)
        {
            if (alert == null) return null;

            string ruleId = alert.RuleId ?? "";
            string text = AlertText(alert);

            if (Contains(ruleId, "IOC"))
            {
                alert.AddWhy("A configured indicator matched the observed process, network, DNS, hash, IP, or domain telemetry.");
            }

            if (Contains(ruleId, "ENCODED") || Contains(text, "-encodedcommand") || Contains(text, "base64"))
            {
                alert.AddWhy("Encoded or base64-like command content was observed, which is common in loader and RAT staging chains.");
            }

            if (Contains(ruleId, "LOLBIN"))
            {
                alert.AddWhy("A living-off-the-land binary matched a monitored suspicious execution or network pattern.");
            }

            if (StartsWith(ruleId, "RAT-"))
            {
                alert.AddWhy("RAT-oriented process, lineage, path, command, or egress traits matched local detection rules.");
            }

            if (StartsWith(ruleId, "PS-"))
            {
                alert.AddWhy("PowerShell telemetry matched a monitored script, command, download, tamper, persistence, or stealth pattern.");
            }

            if (StartsWith(ruleId, "AUDIT-PROC-"))
            {
                alert.AddWhy("Windows process-creation audit telemetry matched suspicious command-line indicators.");
            }

            if (StartsWith(ruleId, "PROC-"))
            {
                alert.AddWhy("Process creation telemetry matched suspicious command, path, parent, network, hash, or reputation traits.");
            }

            if (StartsWith(ruleId, "PERSIST-"))
            {
                alert.AddWhy("Service, scheduled task, startup, registry, or other persistence telemetry changed or appeared suspicious.");
            }

            if (StartsWith(ruleId, "AUTH-"))
            {
                alert.AddWhy("Windows authentication telemetry matched a monitored remote logon, failed logon, or privileged logon pattern.");
            }

            if (EqualsRule(ruleId, "AUTH-LOGON-UNSPECIFIED-SOURCE"))
            {
                alert.AddWhy("Windows reported a remote-style logon type with an unspecified source address, which is ambiguous and often lower-confidence than a concrete remote source.");
            }

            if (EqualsRule(ruleId, "AUTH-REMOTE-SPECIAL-PRIVILEGES"))
            {
                alert.AddWhy("Special privileges were assigned near recent remote logon activity for the same account.");
            }

            if (StartsWith(ruleId, "FILE-"))
            {
                alert.AddWhy("Sysmon file-create telemetry matched a high-risk path, sensitive filename, agent-root boundary, or drop-then-execute pattern.");
            }

            if (StartsWith(ruleId, "DNS-") || StartsWith(ruleId, "NET-DNS-"))
            {
                alert.AddWhy("DNS telemetry matched a suspicious domain, high-entropy query, DoH, resolver, or configured indicator pattern.");
            }

            if (StartsWith(ruleId, "BASELINE-"))
            {
                alert.AddWhy("This behavior was not present in the local baseline after learning mode or warmup.");
            }

            if (StartsWith(ruleId, "REPUTATION-"))
            {
                alert.AddWhy("The process or persistence item was newly observed by local reputation tracking.");
            }

            if (StartsWith(ruleId, "SERVICE-"))
            {
                alert.AddWhy("Arcane EDR service lifecycle, recovery, health, or summary telemetry generated this notification.");
            }

            if (StartsWith(ruleId, "OPENAI-"))
            {
                alert.AddWhy("Compact AI log analysis marked recent redacted activity as alert-worthy or returned a requested test result.");
            }

            if (StartsWith(ruleId, "NET-LISTEN-"))
            {
                alert.AddWhy("A process opened a local listening socket outside the configured listener allowlist.");
            }

            if (StartsWith(ruleId, "NET-INBOUND-"))
            {
                alert.AddWhy("An external host connected to a local listener, which can expose an unexpected service.");
            }

            if (StartsWith(ruleId, "NET-LAN-INBOUND-"))
            {
                alert.AddWhy("A private-network host connected to a local listener on a monitored administration, file-sharing, remote-management, or lateral-movement port.");
            }

            if (StartsWith(ruleId, "NET-LAN-EGRESS-"))
            {
                alert.AddWhy("A process connected to a private-network administration, file-sharing, remote-management, or lateral-movement port.");
            }

            if (StartsWith(ruleId, "NET-EGRESS-"))
            {
                alert.AddWhy("Outbound network activity matched an unusual, high-risk, new, or burst egress pattern.");
            }

            if (EqualsRule(ruleId, "NET-DIRECT-IP-WEB-EGRESS") ||
                EqualsRule(ruleId, "NET-DIRECT-IP-WEB-EGRESS-SIGNED"))
            {
                alert.AddWhy("HTTP or HTTPS egress used a direct IP address without observed hostname context.");
            }

            if (EqualsRule(ruleId, "NET-C2-BEACON-PATTERN") ||
                EqualsRule(ruleId, "NET-BEACON-TIMING-LOW-RISK"))
            {
                alert.AddWhy("Repeated connection timing resembled low-jitter beaconing.");
            }

            if (Contains(ruleId, "HIGH-RISK-PORT") || Contains(ruleId, "UNUSUAL-PORT") || Contains(ruleId, "PORT-MISUSE"))
            {
                alert.AddWhy("The remote port was outside the normal or trusted outbound profile.");
            }

            if (StartsWith(ruleId, "NET-LATERAL-") || StartsWith(ruleId, "NET-LAN-EGRESS-"))
            {
                alert.AddWhy("An untrusted process connected to an internal administration or lateral-movement port.");
            }

            if (StartsWith(ruleId, "APP-"))
            {
                alert.AddWhy("Arcane EDR detected a local monitor configuration or executable integrity change.");
            }

            if (StartsWith(ruleId, "CUSTOM-") || Contains(text, "Custom rule matched"))
            {
                alert.AddWhy("A configured local custom detection rule matched this telemetry.");
            }

            if (alert.Why == null || alert.Why.Count == 0)
            {
                alert.AddWhy("The rule matched configured detection conditions. Review details, entity context, and the recommendation.");
            }

            return alert;
        }

        private static string AlertText(Alert alert)
        {
            return (alert.RuleId ?? "") + " " +
                (alert.Title ?? "") + " " +
                (alert.Body ?? "") + " " +
                (alert.EntitySummary ?? "");
        }

        private static bool StartsWith(string value, string prefix)
        {
            return value != null && value.StartsWith(prefix, StringComparison.OrdinalIgnoreCase);
        }

        private static bool Contains(string value, string term)
        {
            return value != null && value.IndexOf(term, StringComparison.OrdinalIgnoreCase) >= 0;
        }

        private static bool EqualsRule(string value, string expected)
        {
            return value != null && value.Equals(expected, StringComparison.OrdinalIgnoreCase);
        }
    }
}
