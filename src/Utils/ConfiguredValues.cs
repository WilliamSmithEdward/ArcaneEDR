using System;
using System.Collections.Generic;

namespace ArcaneEDR
{
    internal static class ConfiguredValues
    {
        public static bool HasAny(HashSet<string> values)
        {
            if (values == null) return false;
            foreach (string value in values)
            {
                if (!String.IsNullOrWhiteSpace(value)) return true;
            }

            return false;
        }

        public static bool ContainsAnyNormalizedPathTerm(string text, HashSet<string> terms)
        {
            return !String.IsNullOrWhiteSpace(FirstNormalizedPathTerm(text, terms));
        }

        public static string FirstNormalizedPathTerm(string text, HashSet<string> terms)
        {
            if (String.IsNullOrWhiteSpace(text) || terms == null) return "";
            foreach (string term in terms)
            {
                if (!String.IsNullOrWhiteSpace(term) &&
                    text.IndexOf(NormalizePathText(term), StringComparison.OrdinalIgnoreCase) >= 0)
                {
                    return term;
                }
            }

            return "";
        }

        public static string NormalizePathText(string value)
        {
            return value == null ? "" : value.Replace('/', '\\');
        }
    }
}
