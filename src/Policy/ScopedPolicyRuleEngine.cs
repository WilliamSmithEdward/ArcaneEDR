using System;
using System.Collections.Generic;

namespace ArcaneEDR
{
    internal static class PolicyRuleScope
    {
        public const string Alert = "alert";
        public const string RemoteEndpoint = "remote_endpoint";
        public const string Response = "response";
        public const string Report = "report";
    }

    internal interface IScopedPolicyRule<TContext>
    {
        string Scope { get; }
        bool Matches(TContext context);
    }

    internal static class ScopedPolicyRuleEngine
    {
        public static List<TRule> MatchAll<TContext, TRule>(IEnumerable<TRule> rules, string scope, TContext context)
            where TRule : IScopedPolicyRule<TContext>
        {
            List<TRule> result = new List<TRule>();
            if (rules == null) return result;

            foreach (TRule rule in rules)
            {
                if (rule == null) continue;
                if (!ScopeMatches(rule.Scope, scope)) continue;
                if (rule.Matches(context)) result.Add(rule);
            }

            return result;
        }

        public static TRule FirstMatch<TContext, TRule>(IEnumerable<TRule> rules, string scope, TContext context)
            where TRule : class, IScopedPolicyRule<TContext>
        {
            if (rules == null) return null;

            foreach (TRule rule in rules)
            {
                if (rule == null) continue;
                if (!ScopeMatches(rule.Scope, scope)) continue;
                if (rule.Matches(context)) return rule;
            }

            return null;
        }

        private static bool ScopeMatches(string actual, string expected)
        {
            return String.Equals(actual, expected, StringComparison.OrdinalIgnoreCase);
        }
    }
}
