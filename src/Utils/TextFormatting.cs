namespace ArcaneEDR
{
    internal static class TextFormatting
    {
        public static string CompactOrEmpty(string value, int maxLength)
        {
            if (System.String.IsNullOrWhiteSpace(value)) return "";
            string compact = value.Replace("\r", " ").Replace("\n", " ").Trim();
            if (compact.Length <= maxLength) return compact;
            return compact.Substring(0, maxLength) + "...";
        }

        public static string EmptyIfNull(string value)
        {
            return value == null ? "" : value;
        }

        public static string UnknownIfBlank(string value)
        {
            return System.String.IsNullOrWhiteSpace(value) ? "unknown" : value;
        }

        public static bool ContainsIgnoreCase(string text, string value)
        {
            return !System.String.IsNullOrWhiteSpace(text) &&
                !System.String.IsNullOrWhiteSpace(value) &&
                text.IndexOf(value, System.StringComparison.OrdinalIgnoreCase) >= 0;
        }

        public static bool IsTokenBoundary(char value)
        {
            return System.Char.IsWhiteSpace(value) ||
                value == '"' ||
                value == '\'' ||
                value == ',' ||
                value == ';' ||
                value == ')' ||
                value == '(' ||
                value == '|' ||
                value == '\r' ||
                value == '\n';
        }

        public static string PolicyTokenOrUnknown(string value)
        {
            if (System.String.IsNullOrWhiteSpace(value)) return "unknown";
            return value.Trim()
                .Replace(" ", "_")
                .Replace(",", "_")
                .Replace(";", "_")
                .Replace("|", "_")
                .Replace("\r", "")
                .Replace("\n", "");
        }
    }
}
