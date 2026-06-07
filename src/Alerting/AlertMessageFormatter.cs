using System;
using System.Globalization;

namespace ArcaneEDR
{
    internal static class AlertMessageFormatter
    {
        public static string BuildSubject(Alert alert)
        {
            string title = alert.Title;
            if (IsServiceLifecycleAlert(alert.RuleId))
            {
                title += " (" + alert.TimestampUtc.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture) + " UTC)";
            }

            return "[Arcane EDR][" + alert.Severity + "][" + alert.RuleId + "] " + title;
        }

        public static string BuildHtml(Alert alert)
        {
            return "<html><body>" +
                "<h2>" + HtmlEscape(alert.Title) + "</h2>" +
                "<p><strong>Rule:</strong> " + HtmlEscape(alert.RuleId) + "</p>" +
                "<p><strong>Severity:</strong> " + HtmlEscape(alert.Severity) + "</p>" +
                "<p><strong>Score:</strong> " + alert.Score.ToString(CultureInfo.InvariantCulture) + "</p>" +
                "<p><strong>UTC:</strong> " + HtmlEscape(alert.TimestampUtc.ToString("yyyy-MM-ddTHH:mm:ssZ", CultureInfo.InvariantCulture)) + "</p>" +
                "<h3>Details</h3><pre>" + HtmlEscape(alert.Body) + "</pre>" +
                "<h3>Recommendation</h3><pre>" + HtmlEscape(alert.Recommendation) + "</pre>" +
                "<h3>Entity</h3><pre>" + HtmlEscape(alert.EntitySummary) + "</pre>" +
                "</body></html>";
        }

        public static string BuildPlainText(Alert alert)
        {
            return
                alert.Title + Environment.NewLine + Environment.NewLine +
                "Rule: " + alert.RuleId + Environment.NewLine +
                "Severity: " + alert.Severity + Environment.NewLine +
                "Score: " + alert.Score.ToString(CultureInfo.InvariantCulture) + Environment.NewLine +
                "UTC: " + alert.TimestampUtc.ToString("yyyy-MM-ddTHH:mm:ssZ", CultureInfo.InvariantCulture) + Environment.NewLine + Environment.NewLine +
                "Details" + Environment.NewLine +
                NullToEmpty(alert.Body) + Environment.NewLine + Environment.NewLine +
                "Recommendation" + Environment.NewLine +
                NullToEmpty(alert.Recommendation) + Environment.NewLine + Environment.NewLine +
                "Entity" + Environment.NewLine +
                NullToEmpty(alert.EntitySummary);
        }

        public static string Compact(string value, int maxLength)
        {
            if (String.IsNullOrWhiteSpace(value)) return "";

            string compact = value.Replace("\r", " ").Replace("\n", " ").Trim();
            if (compact.Length <= maxLength) return compact;
            return compact.Substring(0, maxLength) + "...";
        }

        private static bool IsServiceLifecycleAlert(string ruleId)
        {
            return ruleId != null &&
                (ruleId.Equals("SERVICE-STARTED", StringComparison.OrdinalIgnoreCase) ||
                 ruleId.Equals("SERVICE-RECOVERED-AFTER-UNCLEAN-STOP", StringComparison.OrdinalIgnoreCase) ||
                 ruleId.Equals("SERVICE-STOPPED", StringComparison.OrdinalIgnoreCase));
        }

        private static string HtmlEscape(string value)
        {
            if (value == null) return "";
            return value
                .Replace("&", "&amp;")
                .Replace("<", "&lt;")
                .Replace(">", "&gt;")
                .Replace("\"", "&quot;");
        }

        private static string NullToEmpty(string value)
        {
            return value ?? "";
        }
    }
}
