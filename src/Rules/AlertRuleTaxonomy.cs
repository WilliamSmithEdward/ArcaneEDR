using System;

namespace ArcaneEDR
{
    internal static class AlertRuleTaxonomy
    {
        public const string CategoryNetwork = "Network";
        public const string CategoryDns = "DNS";
        public const string CategoryPowerShell = "PowerShell";
        public const string CategoryPersistence = "Persistence";
        public const string CategoryAuth = "Auth";
        public const string CategoryFile = "File";
        public const string CategoryProcess = "Process";
        public const string CategoryAgent = "Agent";
        public const string CategoryResponse = "Response";
        public const string CategoryRat = "RAT";
        public const string CategoryAi = "AI";
        public const string CategoryHealth = "Health";
        public const string CategoryIntegrity = "Integrity";
        public const string CategoryBaseline = "Baseline";
        public const string CategoryReputation = "Reputation";
        public const string CategoryCustom = "Custom";
        public const string CategoryTest = "Test";
        public const string CategoryGeneral = "General";

        public const string PrefixNetworkDns = "NET-DNS-";
        public const string PrefixNetwork = "NET-";
        public const string PrefixDns = "DNS-";
        public const string PrefixPowerShell = "PS-";
        public const string PrefixPowerShellDefender = "PS-DEFENDER";
        public const string PrefixPowerShellEncoded = "PS-ENCODED-";
        public const string PrefixPowerShellPersistence = "PS-PERSIST";
        public const string PrefixPersistence = "PERSIST-";
        public const string PrefixAuth = "AUTH-";
        public const string PrefixAuthRemote = "AUTH-REMOTE-";
        public const string PrefixFile = "FILE-";
        public const string PrefixProcess = "PROC-";
        public const string PrefixAuditProcess = "AUDIT-PROC-";
        public const string PrefixAgent = "AGENT-";
        public const string PrefixAgentAdmin = "AGENT-ADMIN-";
        public const string PrefixAgentSecret = "AGENT-SECRET-";
        public const string PrefixAgentSupply = "AGENT-SUPPLY-";
        public const string PrefixResponse = "RESPONSE-";
        public const string PrefixRat = "RAT-";
        public const string PrefixAi = "AI-";
        public const string PrefixAiLogAnalysis = "AI-LOG-ANALYSIS-";
        public const string PrefixService = "SERVICE-";
        public const string PrefixApp = "APP-";
        public const string PrefixBaseline = "BASELINE-";
        public const string PrefixReputation = "REPUTATION-";
        public const string PrefixCustom = "CUSTOM-";
        public const string PrefixTest = "TEST-";
        public const string PrefixNetworkListen = "NET-LISTEN-";
        public const string PrefixNetworkInbound = "NET-INBOUND-";
        public const string PrefixNetworkLan = "NET-LAN-";
        public const string PrefixNetworkLanInbound = "NET-LAN-INBOUND-";
        public const string PrefixNetworkLanEgress = "NET-LAN-EGRESS-";
        public const string PrefixNetworkEgress = "NET-EGRESS-";
        public const string PrefixNetworkLateral = "NET-LATERAL-";
        public const string PrefixNetworkC2Beacon = "NET-C2-BEACON";

        public const string RuleServiceStarted = "SERVICE-STARTED";
        public const string RuleServiceRecoveredAfterUncleanStop = "SERVICE-RECOVERED-AFTER-UNCLEAN-STOP";
        public const string RuleServiceStopped = "SERVICE-STOPPED";
        public const string RuleServiceDailySummary = "SERVICE-DAILY-SUMMARY";
        public const string RuleServiceHealthTest = "SERVICE-HEALTH-TEST";
        public const string RuleAiLogAnalysisTest = "AI-LOG-ANALYSIS-TEST";
        public const string RuleAiLogAnalysisAlert = "AI-LOG-ANALYSIS-ALERT";
        public const string RuleTestAlert = "TEST-ALERT";
        public const string RuleTestAlertDelivery = "TEST-ALERT-DELIVERY";
        public const string RuleAuthLogonUnspecifiedSource = "AUTH-LOGON-UNSPECIFIED-SOURCE";
        public const string RuleAuthRemoteSpecialPrivileges = "AUTH-REMOTE-SPECIAL-PRIVILEGES";
        public const string RuleNetworkDirectIpWebEgress = "NET-DIRECT-IP-WEB-EGRESS";
        public const string RuleNetworkDirectIpWebEgressSigned = "NET-DIRECT-IP-WEB-EGRESS-SIGNED";
        public const string RuleNetworkRemotePolicyBlocked = "NET-REMOTE-POLICY-BLOCKED";
        public const string RuleNetworkRemotePolicyCritical = "NET-REMOTE-POLICY-CRITICAL";
        public const string RuleNetworkC2BeaconPattern = "NET-C2-BEACON-PATTERN";
        public const string RuleNetworkBeaconTimingLowRisk = "NET-BEACON-TIMING-LOW-RISK";
        public const string RuleNetworkTrustedAltWebPort = "NET-EGRESS-TRUSTED-ALT-WEB-PORT";

        private static readonly RuleCategory[] CategoriesByPrefix = new[]
        {
            new RuleCategory(PrefixNetworkDns, CategoryDns),
            new RuleCategory(PrefixNetwork, CategoryNetwork),
            new RuleCategory(PrefixDns, CategoryDns),
            new RuleCategory(PrefixPowerShell, CategoryPowerShell),
            new RuleCategory(PrefixPersistence, CategoryPersistence),
            new RuleCategory(PrefixAuth, CategoryAuth),
            new RuleCategory(PrefixFile, CategoryFile),
            new RuleCategory(PrefixProcess, CategoryProcess),
            new RuleCategory(PrefixAuditProcess, CategoryProcess),
            new RuleCategory(PrefixAgent, CategoryAgent),
            new RuleCategory(PrefixResponse, CategoryResponse),
            new RuleCategory(PrefixRat, CategoryRat),
            new RuleCategory(PrefixAi, CategoryAi),
            new RuleCategory(PrefixService, CategoryHealth),
            new RuleCategory(PrefixApp, CategoryIntegrity),
            new RuleCategory(PrefixBaseline, CategoryBaseline),
            new RuleCategory(PrefixReputation, CategoryReputation),
            new RuleCategory(PrefixCustom, CategoryCustom),
            new RuleCategory(PrefixTest, CategoryTest)
        };

        private static readonly string[] KnownCategories = new[]
        {
            CategoryNetwork,
            CategoryDns,
            CategoryPowerShell,
            CategoryPersistence,
            CategoryAuth,
            CategoryFile,
            CategoryProcess,
            CategoryAgent,
            CategoryResponse,
            CategoryRat,
            CategoryAi,
            CategoryHealth,
            CategoryIntegrity,
            CategoryBaseline,
            CategoryReputation,
            CategoryCustom,
            CategoryTest,
            CategoryGeneral
        };

        public static string CategoryFor(string ruleId)
        {
            foreach (RuleCategory entry in CategoriesByPrefix)
            {
                if (HasPrefix(ruleId, entry.Prefix)) return entry.Category;
            }

            return CategoryGeneral;
        }

        public static bool IsKnownCategory(string category)
        {
            if (String.IsNullOrWhiteSpace(category)) return false;

            foreach (string known in KnownCategories)
            {
                if (category.Equals(known, StringComparison.OrdinalIgnoreCase)) return true;
            }

            return false;
        }

        public static bool IsServiceLifecycleRule(string ruleId)
        {
            return EqualsRule(ruleId, RuleServiceStarted) ||
                EqualsRule(ruleId, RuleServiceRecoveredAfterUncleanStop) ||
                EqualsRule(ruleId, RuleServiceStopped);
        }

        public static bool IsDirectExternalRule(string ruleId)
        {
            return HasPrefix(ruleId, PrefixService) ||
                HasPrefix(ruleId, PrefixAiLogAnalysis);
        }

        public static bool IsDailySummaryRule(string ruleId)
        {
            return EqualsRule(ruleId, RuleServiceDailySummary);
        }

        public static bool IsDnsRule(string ruleId)
        {
            return HasPrefix(ruleId, PrefixDns) ||
                HasPrefix(ruleId, PrefixNetworkDns);
        }

        public static bool IsResponseRule(string ruleId)
        {
            return HasPrefix(ruleId, PrefixResponse);
        }

        public static bool HasAnyPrefix(string ruleId, params string[] prefixes)
        {
            if (prefixes == null) return false;

            foreach (string prefix in prefixes)
            {
                if (HasPrefix(ruleId, prefix)) return true;
            }

            return false;
        }

        public static bool HasPrefix(string ruleId, string prefix)
        {
            return !String.IsNullOrWhiteSpace(prefix) &&
                ruleId != null &&
                ruleId.StartsWith(prefix, StringComparison.OrdinalIgnoreCase);
        }

        public static bool EqualsRule(string ruleId, string expected)
        {
            return ruleId != null &&
                expected != null &&
                ruleId.Equals(expected, StringComparison.OrdinalIgnoreCase);
        }

        private sealed class RuleCategory
        {
            public readonly string Prefix;
            public readonly string Category;

            public RuleCategory(string prefix, string category)
            {
                Prefix = prefix;
                Category = category;
            }
        }
    }
}
