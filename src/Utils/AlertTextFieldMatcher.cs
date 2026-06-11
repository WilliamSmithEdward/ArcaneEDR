using System;

namespace ArcaneEDR
{
    internal static class AlertTextFieldMatcher
    {
        public static bool FieldValueMatches(string text, string fieldName, string expected)
        {
            if (String.IsNullOrWhiteSpace(text) ||
                String.IsNullOrWhiteSpace(fieldName) ||
                String.IsNullOrWhiteSpace(expected))
            {
                return false;
            }

            int index = text.IndexOf(fieldName, StringComparison.OrdinalIgnoreCase);
            while (index >= 0)
            {
                int start = index + fieldName.Length;
                if (ValueMatchesAt(text, start, expected)) return true;
                index = text.IndexOf(fieldName, index + fieldName.Length, StringComparison.OrdinalIgnoreCase);
            }

            return false;
        }

        public static bool ValueMatchesAt(string text, int start, string expected)
        {
            int index = start;
            while (index < text.Length && Char.IsWhiteSpace(text[index]))
            {
                index++;
            }

            if (index < text.Length && text[index] == '"') index++;
            if (index + expected.Length > text.Length) return false;
            if (!text.Substring(index, expected.Length).Equals(expected, StringComparison.OrdinalIgnoreCase)) return false;

            int after = index + expected.Length;
            return after >= text.Length || TextFormatting.IsTokenBoundary(text[after]);
        }
    }
}
