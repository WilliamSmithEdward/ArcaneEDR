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
                "<p><strong>Category:</strong> " + HtmlEscape(AlertRulePolicy.AlertCategory(alert)) + "</p>" +
                "<p><strong>Severity:</strong> " + HtmlEscape(alert.Severity) + "</p>" +
                "<p><strong>Score:</strong> " + alert.Score.ToString(CultureInfo.InvariantCulture) + "</p>" +
                "<p><strong>UTC:</strong> " + HtmlEscape(alert.TimestampUtc.ToString("yyyy-MM-ddTHH:mm:ssZ", CultureInfo.InvariantCulture)) + "</p>" +
                BuildWhyHtml(alert) +
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
                "Category: " + AlertRulePolicy.AlertCategory(alert) + Environment.NewLine +
                "Severity: " + alert.Severity + Environment.NewLine +
                "Score: " + alert.Score.ToString(CultureInfo.InvariantCulture) + Environment.NewLine +
                "UTC: " + alert.TimestampUtc.ToString("yyyy-MM-ddTHH:mm:ssZ", CultureInfo.InvariantCulture) + Environment.NewLine + Environment.NewLine +
                BuildWhyPlainText(alert) +
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

        private static string BuildWhyHtml(Alert alert)
        {
            if (alert.Why == null || alert.Why.Count == 0) return "";

            string html = "<h3>Why This Alerted</h3><ul>";
            foreach (string reason in alert.Why)
            {
                html += "<li>" + HtmlEscape(reason) + "</li>";
            }

            return html + "</ul>";
        }

        private static string BuildWhyPlainText(Alert alert)
        {
            if (alert.Why == null || alert.Why.Count == 0) return "";

            string text = "Why This Alerted" + Environment.NewLine;
            foreach (string reason in alert.Why)
            {
                text += "- " + reason + Environment.NewLine;
            }

            return text + Environment.NewLine;
        }

        private static bool IsServiceLifecycleAlert(string ruleId)
        {
            return AlertRuleCatalog.IsServiceLifecycleAlert(ruleId);
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
