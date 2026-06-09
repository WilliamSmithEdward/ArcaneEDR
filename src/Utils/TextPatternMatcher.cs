using System;
using System.Collections.Generic;
using System.Text.RegularExpressions;

namespace ArcaneEDR
{
    internal static class TextPatternMatcher
    {
        public static bool IsMatch(string text, IEnumerable<string> entries)
        {
            if (String.IsNullOrWhiteSpace(text) || entries == null) return false;

            foreach (string entry in entries)
            {
                if (EntryMatches(text, entry)) return true;
            }

            return false;
        }

        public static bool IsRegexEntry(string entry)
        {
            if (String.IsNullOrWhiteSpace(entry)) return false;
            string trimmed = entry.Trim();
            return trimmed.StartsWith("regex:", StringComparison.OrdinalIgnoreCase) ||
                trimmed.StartsWith("re:", StringComparison.OrdinalIgnoreCase) ||
                (trimmed.Length > 2 && trimmed[0] == '/' && trimmed[trimmed.Length - 1] == '/');
        }

        public static bool TryGetRegexPattern(string entry, out string pattern)
        {
            pattern = "";
            if (!IsRegexEntry(entry)) return false;

            string trimmed = entry.Trim();
            if (trimmed.StartsWith("regex:", StringComparison.OrdinalIgnoreCase))
            {
                pattern = trimmed.Substring("regex:".Length);
                return true;
            }

            if (trimmed.StartsWith("re:", StringComparison.OrdinalIgnoreCase))
            {
                pattern = trimmed.Substring("re:".Length);
                return true;
            }

            pattern = trimmed.Substring(1, trimmed.Length - 2);
            return true;
        }

        public static bool TryValidateRegexEntry(string entry, out string message)
        {
            message = "";
            string pattern;
            if (!TryGetRegexPattern(entry, out pattern)) return true;

            if (String.IsNullOrWhiteSpace(pattern))
            {
                message = "regex pattern is empty";
                return false;
            }

            try
            {
                Regex.Match("", pattern, RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
                return true;
            }
            catch (Exception ex)
            {
                message = ex.Message;
                return false;
            }
        }

        private static bool EntryMatches(string text, string entry)
        {
            if (String.IsNullOrWhiteSpace(entry)) return false;

            string pattern;
            if (TryGetRegexPattern(entry, out pattern))
            {
                if (String.IsNullOrWhiteSpace(pattern)) return false;
                try
                {
                    return Regex.IsMatch(text, pattern, RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
                }
                catch
                {
                    return false;
                }
            }

            return text.IndexOf(entry.Trim(), StringComparison.OrdinalIgnoreCase) >= 0;
        }
    }
}
