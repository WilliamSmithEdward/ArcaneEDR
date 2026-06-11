using System;
using System.Globalization;

namespace ArcaneEDR
{
    internal static class PolicyInspectConsole
    {
        public static int Run(string baseDirectory, string[] args)
        {
            MonitorConfig config = MonitorConfig.Load(baseDirectory);
            DetectionPolicy detectionPolicy = DetectionPolicy.Load(config.DetectionPolicyFile);
            RemoteEndpointPolicy remoteEndpointPolicy = RemoteEndpointPolicy.Load(config.RemoteEndpointPolicyFile);
            bool json = HasFlag(args, "--json");

            if (json)
            {
                Console.WriteLine(ToJson(config, detectionPolicy, remoteEndpointPolicy));
            }
            else
            {
                PrintText(config, detectionPolicy, remoteEndpointPolicy);
            }

            return detectionPolicy.Errors.Count == 0 && remoteEndpointPolicy.Errors.Count == 0 ? 0 : 1;
        }

        private static void PrintText(MonitorConfig config, DetectionPolicy detectionPolicy, RemoteEndpointPolicy remoteEndpointPolicy)
        {
            Console.WriteLine("Unified policy");
            Console.WriteLine("PolicyFile=" + config.PolicyFile);
            Console.WriteLine("Storage=JSONL evidence; no database required");
            Console.WriteLine("Scope " + PolicyRuleScope.Alert + " rules=" + detectionPolicy.Rules.Count.ToString(CultureInfo.InvariantCulture) + " enabled=" + CountEnabledDetectionRules(detectionPolicy).ToString(CultureInfo.InvariantCulture));
            Console.WriteLine("Scope " + PolicyRuleScope.RemoteEndpoint + " rules=" + remoteEndpointPolicy.Rules.Count.ToString(CultureInfo.InvariantCulture) + " enabled=" + CountEnabledRemoteRules(remoteEndpointPolicy).ToString(CultureInfo.InvariantCulture));
            int responseRules = ResponsePolicyRule.Build(config).Count;
            Console.WriteLine("Scope " + PolicyRuleScope.Response +
                " rules=" + responseRules.ToString(CultureInfo.InvariantCulture) +
                " enabled=" + responseRules.ToString(CultureInfo.InvariantCulture) +
                " allowed_rules=" + CountConfigured(config.ResponseAllowedRuleIds).ToString(CultureInfo.InvariantCulture) +
                " allowed_categories=" + CountConfigured(config.ResponseAllowedCategories).ToString(CultureInfo.InvariantCulture) +
                " blocked_rules=" + CountConfigured(config.ResponseBlockedRuleIds).ToString(CultureInfo.InvariantCulture) +
                " blocked_categories=" + CountConfigured(config.ResponseBlockedCategories).ToString(CultureInfo.InvariantCulture));
            Console.WriteLine("Allowlists trusted_processes=" + CountConfigured(config.TrustedProcesses).ToString(CultureInfo.InvariantCulture) +
                " allowed_remote_countries=" + CountConfigured(config.AllowedRemoteCountries).ToString(CultureInfo.InvariantCulture) +
                " allowed_outbound_ports=" + config.AllowedOutboundPorts.Count.ToString(CultureInfo.InvariantCulture));
            Console.WriteLine("Blocklists domains=" + CountConfigured(config.BlockedDomains).ToString(CultureInfo.InvariantCulture) +
                " hashes=" + CountConfigured(config.BlockedHashes).ToString(CultureInfo.InvariantCulture));
            PrintPolicyMessages("DetectionPolicy", detectionPolicy.Errors, detectionPolicy.Warnings);
            PrintPolicyMessages("RemoteEndpointPolicy", remoteEndpointPolicy.Errors, remoteEndpointPolicy.Warnings);
        }

        private static string ToJson(MonitorConfig config, DetectionPolicy detectionPolicy, RemoteEndpointPolicy remoteEndpointPolicy)
        {
            return "{" +
                "\"policy_file\":\"" + JsonFields.Escape(config.PolicyFile) + "\"," +
                "\"storage\":\"jsonl\"," +
                "\"scopes\":[" +
                    ScopeJson(PolicyRuleScope.Alert, detectionPolicy.Rules.Count, CountEnabledDetectionRules(detectionPolicy)) + "," +
                    ScopeJson(PolicyRuleScope.RemoteEndpoint, remoteEndpointPolicy.Rules.Count, CountEnabledRemoteRules(remoteEndpointPolicy)) + "," +
                    ResponseScopeJson(config) +
                "]," +
                "\"allowlists\":{" +
                    "\"trusted_processes\":" + CountConfigured(config.TrustedProcesses).ToString(CultureInfo.InvariantCulture) + "," +
                    "\"allowed_remote_countries\":" + CountConfigured(config.AllowedRemoteCountries).ToString(CultureInfo.InvariantCulture) + "," +
                    "\"allowed_outbound_ports\":" + config.AllowedOutboundPorts.Count.ToString(CultureInfo.InvariantCulture) +
                "}," +
                "\"blocklists\":{" +
                    "\"domains\":" + CountConfigured(config.BlockedDomains).ToString(CultureInfo.InvariantCulture) + "," +
                    "\"hashes\":" + CountConfigured(config.BlockedHashes).ToString(CultureInfo.InvariantCulture) +
                "}," +
                "\"errors\":" + (detectionPolicy.Errors.Count + remoteEndpointPolicy.Errors.Count).ToString(CultureInfo.InvariantCulture) + "," +
                "\"warnings\":" + (detectionPolicy.Warnings.Count + remoteEndpointPolicy.Warnings.Count).ToString(CultureInfo.InvariantCulture) +
                "}";
        }

        private static string ScopeJson(string scope, int rules, int enabled)
        {
            return "{\"scope\":\"" + JsonFields.Escape(scope) + "\",\"rules\":" +
                rules.ToString(CultureInfo.InvariantCulture) +
                ",\"enabled\":" + enabled.ToString(CultureInfo.InvariantCulture) + "}";
        }

        private static string ResponseScopeJson(MonitorConfig config)
        {
            int responseRules = ResponsePolicyRule.Build(config).Count;
            return "{\"scope\":\"" + PolicyRuleScope.Response + "\"," +
                "\"rules\":" + responseRules.ToString(CultureInfo.InvariantCulture) + "," +
                "\"enabled\":" + responseRules.ToString(CultureInfo.InvariantCulture) + "," +
                "\"allowed_rules\":" + CountConfigured(config.ResponseAllowedRuleIds).ToString(CultureInfo.InvariantCulture) + "," +
                "\"allowed_categories\":" + CountConfigured(config.ResponseAllowedCategories).ToString(CultureInfo.InvariantCulture) + "," +
                "\"blocked_rules\":" + CountConfigured(config.ResponseBlockedRuleIds).ToString(CultureInfo.InvariantCulture) + "," +
                "\"blocked_categories\":" + CountConfigured(config.ResponseBlockedCategories).ToString(CultureInfo.InvariantCulture) +
                "}";
        }

        private static void PrintPolicyMessages(string name, System.Collections.Generic.List<string> errors, System.Collections.Generic.List<string> warnings)
        {
            foreach (string error in errors)
            {
                Console.WriteLine(name + "Error=" + error);
            }

            foreach (string warning in warnings)
            {
                Console.WriteLine(name + "Warning=" + warning);
            }
        }

        private static int CountEnabledDetectionRules(DetectionPolicy policy)
        {
            int count = 0;
            foreach (DetectionPolicyRule rule in policy.Rules)
            {
                if (rule.Enabled) count++;
            }

            return count;
        }

        private static int CountEnabledRemoteRules(RemoteEndpointPolicy policy)
        {
            int count = 0;
            foreach (RemoteEndpointPolicyRule rule in policy.Rules)
            {
                if (rule.Enabled) count++;
            }

            return count;
        }

        private static int CountConfigured(System.Collections.Generic.HashSet<string> values)
        {
            int count = 0;
            if (values == null) return count;
            foreach (string value in values)
            {
                if (!String.IsNullOrWhiteSpace(value)) count++;
            }

            return count;
        }

        private static bool HasFlag(string[] args, string flag)
        {
            foreach (string arg in args ?? new string[0])
            {
                if (arg.Equals(flag, StringComparison.OrdinalIgnoreCase)) return true;
            }

            return false;
        }
    }
}
