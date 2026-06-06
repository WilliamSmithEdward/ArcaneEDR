using System;
using System.Collections.Generic;

namespace ArcaneEDR
{
    internal static class TermGroupRules
    {
        public static bool MatchesAnyGroup(string text, HashSet<string> groups)
        {
            if (String.IsNullOrWhiteSpace(text) || groups == null || groups.Count == 0)
            {
                return false;
            }

            foreach (string group in groups)
            {
                if (MatchesGroup(text, group)) return true;
            }

            return false;
        }

        private static bool MatchesGroup(string text, string group)
        {
            if (String.IsNullOrWhiteSpace(group)) return false;

            string[] terms = group.Split('|');
            bool hasTerm = false;
            foreach (string rawTerm in terms)
            {
                string term = rawTerm.Trim();
                if (term.Length == 0) continue;

                hasTerm = true;
                if (text.IndexOf(term, StringComparison.OrdinalIgnoreCase) < 0)
                {
                    return false;
                }
            }

            return hasTerm;
        }
    }
}
