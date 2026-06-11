using System;

namespace ArcaneEDR
{
    internal static class AlertAnnotationText
    {
        public static string AppendLine(string value, string line)
        {
            if (String.IsNullOrWhiteSpace(value)) return line;
            return value + Environment.NewLine + line;
        }

        public static string AppendEntity(string value, string addition)
        {
            if (String.IsNullOrWhiteSpace(value)) return addition;
            return value + " " + addition;
        }

        public static string NormalizeReasonToken(string value, int maxLength, string pipeReplacement)
        {
            if (String.IsNullOrWhiteSpace(value)) return "";

            string normalized = value.Trim()
                .Replace("\\", "/")
                .Replace(" ", "_")
                .Replace(",", "_")
                .Replace(";", "_")
                .Replace("|", pipeReplacement ?? "_")
                .Replace("\r", "")
                .Replace("\n", "");

            if (normalized.Length <= maxLength) return normalized;
            return normalized.Substring(0, maxLength);
        }

        public static string CompactOrNotSpecified(string value, int maxLength)
        {
            if (String.IsNullOrWhiteSpace(value)) return "not specified";
            string compact = value.Replace("\r", " ").Replace("\n", " ").Trim();
            if (compact.Length <= maxLength) return compact;
            return compact.Substring(0, Math.Max(0, maxLength - 3)) + "...";
        }
    }
}
