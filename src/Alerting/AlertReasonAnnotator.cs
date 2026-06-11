using System;

namespace ArcaneEDR
{
    internal static class AlertReasonAnnotator
    {
        public static Alert Annotate(Alert alert)
        {
            if (alert == null) return null;

            string ruleId = alert.RuleId ?? "";
            string text = AlertText.Build(alert);

            if (TextFormatting.ContainsIgnoreCase(ruleId, "IOC"))
            {
                alert.AddWhy("A configured indicator matched the observed process, network, DNS, hash, IP, or domain telemetry.");
            }

            if (TextFormatting.ContainsIgnoreCase(ruleId, "ENCODED") || TextFormatting.ContainsIgnoreCase(text, "-encodedcommand") || TextFormatting.ContainsIgnoreCase(text, "base64"))
            {
                alert.AddWhy("Encoded or base64-like command content was observed, which is common in loader and RAT staging chains.");
            }

            if (TextFormatting.ContainsIgnoreCase(ruleId, "LOLBIN"))
            {
                alert.AddWhy("A living-off-the-land binary matched a monitored suspicious execution or network pattern.");
            }

            if (AlertRuleTaxonomy.HasPrefix(ruleId, AlertRuleTaxonomy.PrefixRat))
            {
                alert.AddWhy("RAT-oriented process, lineage, path, command, or egress traits matched local detection rules.");
            }

            if (AlertRuleTaxonomy.HasPrefix(ruleId, AlertRuleTaxonomy.PrefixPowerShell))
            {
                alert.AddWhy("PowerShell telemetry matched a monitored script, command, download, tamper, persistence, or stealth pattern.");
            }

            if (AlertRuleTaxonomy.HasPrefix(ruleId, AlertRuleTaxonomy.PrefixAuditProcess))
            {
                alert.AddWhy("Windows process-creation audit telemetry matched suspicious command-line indicators.");
            }

            if (AlertRuleTaxonomy.HasPrefix(ruleId, AlertRuleTaxonomy.PrefixProcess))
            {
                alert.AddWhy("Process creation telemetry matched suspicious command, path, parent, network, hash, or reputation traits.");
            }

            if (AlertRuleTaxonomy.IsResponseRule(ruleId))
            {
                alert.AddWhy("Arcane response follow-up telemetry matched a monitored post-response condition.");
            }

            if (AlertRuleTaxonomy.HasPrefix(ruleId, AlertRuleTaxonomy.PrefixAgent))
            {
                alert.AddWhy("Configured agent-context telemetry matched an alert-only workstation guardrail.");
            }

            if (AlertRuleTaxonomy.HasPrefix(ruleId, AlertRuleTaxonomy.PrefixPersistence))
            {
                alert.AddWhy("Service, scheduled task, startup, registry, or other persistence telemetry changed or appeared suspicious.");
            }

            if (AlertRuleTaxonomy.HasPrefix(ruleId, AlertRuleTaxonomy.PrefixAuth))
            {
                alert.AddWhy("Windows authentication telemetry matched a monitored remote logon, failed logon, or privileged logon pattern.");
            }

            if (AlertRuleTaxonomy.EqualsRule(ruleId, AlertRuleTaxonomy.RuleAuthLogonUnspecifiedSource))
            {
                alert.AddWhy("Windows reported a remote-style logon type with an unspecified source address, which is ambiguous and often lower-confidence than a concrete remote source.");
            }

            if (AlertRuleTaxonomy.EqualsRule(ruleId, AlertRuleTaxonomy.RuleAuthRemoteSpecialPrivileges))
            {
                alert.AddWhy("Special privileges were assigned near recent remote logon activity for the same account.");
            }

            if (AlertRuleTaxonomy.HasPrefix(ruleId, AlertRuleTaxonomy.PrefixFile))
            {
                alert.AddWhy("Sysmon file-create telemetry matched a high-risk path, sensitive filename, agent-root boundary, or drop-then-execute pattern.");
            }

            if (AlertRuleTaxonomy.IsDnsRule(ruleId))
            {
                alert.AddWhy("DNS telemetry matched a suspicious domain, high-entropy query, DoH, resolver, or configured indicator pattern.");
            }

            if (AlertRuleTaxonomy.HasPrefix(ruleId, AlertRuleTaxonomy.PrefixBaseline))
            {
                alert.AddWhy("This behavior was not present in the local baseline after learning mode or warmup.");
            }

            if (AlertRuleTaxonomy.HasPrefix(ruleId, AlertRuleTaxonomy.PrefixReputation))
            {
                alert.AddWhy("The process or persistence item was newly observed by local reputation tracking.");
            }

            if (AlertRuleTaxonomy.HasPrefix(ruleId, AlertRuleTaxonomy.PrefixService))
            {
                alert.AddWhy("Arcane EDR service lifecycle, recovery, health, or summary telemetry generated this notification.");
            }

            if (AlertRuleTaxonomy.HasPrefix(ruleId, AlertRuleTaxonomy.PrefixAi))
            {
                alert.AddWhy("Compact AI log analysis marked recent redacted activity as alert-worthy or returned a requested test result.");
            }

            if (AlertRuleTaxonomy.HasPrefix(ruleId, AlertRuleTaxonomy.PrefixNetworkListen))
            {
                alert.AddWhy("A process opened a local listening socket outside the configured listener allowlist.");
            }

            if (AlertRuleTaxonomy.HasPrefix(ruleId, AlertRuleTaxonomy.PrefixNetworkInbound))
            {
                alert.AddWhy("An external host connected to a local listener, which can expose an unexpected service.");
            }

            if (AlertRuleTaxonomy.HasPrefix(ruleId, AlertRuleTaxonomy.PrefixNetworkLanInbound))
            {
                alert.AddWhy("A private-network host connected to a local listener on a monitored administration, file-sharing, remote-management, or lateral-movement port.");
            }

            if (AlertRuleTaxonomy.HasPrefix(ruleId, AlertRuleTaxonomy.PrefixNetworkLanEgress))
            {
                alert.AddWhy("A process connected to a private-network administration, file-sharing, remote-management, or lateral-movement port.");
            }

            if (AlertRuleTaxonomy.HasPrefix(ruleId, AlertRuleTaxonomy.PrefixNetworkEgress))
            {
                alert.AddWhy("Outbound network activity matched an unusual, high-risk, new, or burst egress pattern.");
            }

            if (AlertRuleTaxonomy.EqualsRule(ruleId, AlertRuleTaxonomy.RuleNetworkDirectIpWebEgress) ||
                AlertRuleTaxonomy.EqualsRule(ruleId, AlertRuleTaxonomy.RuleNetworkDirectIpWebEgressSigned))
            {
                alert.AddWhy("HTTP or HTTPS egress used a direct IP address without observed hostname context.");
            }

            if (AlertRuleTaxonomy.EqualsRule(ruleId, AlertRuleTaxonomy.RuleNetworkRemotePolicyBlocked) ||
                AlertRuleTaxonomy.EqualsRule(ruleId, AlertRuleTaxonomy.RuleNetworkRemotePolicyCritical))
            {
                alert.AddWhy("Ordered remote endpoint policy marked this destination blocked, critical, or escalated by paired context.");
            }

            if (AlertRuleTaxonomy.EqualsRule(ruleId, AlertRuleTaxonomy.RuleNetworkC2BeaconPattern) ||
                AlertRuleTaxonomy.EqualsRule(ruleId, AlertRuleTaxonomy.RuleNetworkBeaconTimingLowRisk))
            {
                alert.AddWhy("Repeated connection timing resembled low-jitter beaconing.");
            }

            if (TextFormatting.ContainsIgnoreCase(ruleId, "HIGH-RISK-PORT") || TextFormatting.ContainsIgnoreCase(ruleId, "UNUSUAL-PORT") || TextFormatting.ContainsIgnoreCase(ruleId, "PORT-MISUSE"))
            {
                alert.AddWhy("The remote port was outside the normal or trusted outbound profile.");
            }

            if (AlertRuleTaxonomy.EqualsRule(ruleId, AlertRuleTaxonomy.RuleNetworkTrustedAltWebPort))
            {
                alert.AddWhy("A trusted signed process used a common alternate web/proxy port that is tracked as local context.");
            }

            if (AlertRuleTaxonomy.HasPrefix(ruleId, AlertRuleTaxonomy.PrefixNetworkLateral) ||
                AlertRuleTaxonomy.HasPrefix(ruleId, AlertRuleTaxonomy.PrefixNetworkLanEgress))
            {
                alert.AddWhy("An untrusted process connected to an internal administration or lateral-movement port.");
            }

            if (AlertRuleTaxonomy.HasPrefix(ruleId, AlertRuleTaxonomy.PrefixApp))
            {
                alert.AddWhy("Arcane EDR detected a local monitor configuration or executable integrity change.");
            }

            if (AlertRuleTaxonomy.HasPrefix(ruleId, AlertRuleTaxonomy.PrefixCustom) || TextFormatting.ContainsIgnoreCase(text, "Custom rule matched"))
            {
                alert.AddWhy("A configured local custom detection rule matched this telemetry.");
            }

            if (alert.Why == null || alert.Why.Count == 0)
            {
                alert.AddWhy("The rule matched configured detection conditions. Review details, entity context, and the recommendation.");
            }

            return alert;
        }

    }
}
