using System;
using System.Collections.Generic;
using System.Globalization;

namespace ArcaneEDR
{
    internal static class AlertMessageFormatter
    {
        private const int EmailContentWidthPixels = 760;
        private const string WrapStyle = "word-break:break-word;overflow-wrap:anywhere;";

        public static string BuildSubject(Alert alert)
        {
            if (IsDailySummary(alert.RuleId))
            {
                return "[Arcane EDR][daily] Daily report " +
                    alert.TimestampUtc.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture) + " UTC";
            }

            string title = alert.Title;
            if (IsServiceLifecycleAlert(alert.RuleId))
            {
                title += " (" + alert.TimestampUtc.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture) + " UTC)";
            }

            return "[Arcane EDR][" + alert.Severity + "][" + alert.RuleId + "] " + title;
        }

        public static string BuildHtml(Alert alert)
        {
            if (IsDailySummary(alert.RuleId))
            {
                return BuildDailyReportHtml(alert);
            }

            AlertPresentation presentation = AlertPresentation.FromAlert(alert);
            return BeginEmailHtml() +
                "<h2>" + HtmlEscape(presentation.Title) + "</h2>" +
                BuildAlertFieldHtml("Rule", presentation.RuleId) +
                BuildAlertFieldHtml("Category", presentation.Category) +
                BuildAlertFieldHtml("Source", presentation.SourceSummary) +
                BuildRemoteHeaderFieldsHtml(presentation.Remote) +
                BuildAlertFieldHtml("Maintenance Context", alert.MaintenanceContext ? "true" : "false") +
                BuildAlertFieldHtml("Severity", alert.Severity) +
                BuildAlertFieldHtml("Score", alert.Score.ToString(CultureInfo.InvariantCulture)) +
                BuildAlertFieldHtml("UTC", UtcTimestamp.Format(alert.TimestampUtc)) +
                BuildAlertFieldHtml("System Local Time", alert.SystemLocalTime) +
                BuildScoreContextHtml() +
                BuildWhyHtml(alert) +
                "<h3>Details</h3>" + BuildWrappedPreHtml(alert.Body) +
                "<h3>Recommendation</h3>" + BuildWrappedPreHtml(alert.Recommendation) +
                "<h3>Entity</h3>" + BuildWrappedPreHtml(alert.EntitySummary) +
                EndEmailHtml();
        }

        public static string BuildPlainText(Alert alert)
        {
            if (IsDailySummary(alert.RuleId))
            {
                return NullToEmpty(alert.Body) + Environment.NewLine + BuildScoreContextPlainText();
            }

            AlertPresentation presentation = AlertPresentation.FromAlert(alert);
            string remoteHeaderLines = BuildRemoteHeaderFieldsPlainText(presentation.Remote);

            return
                presentation.Title + Environment.NewLine + Environment.NewLine +
                "Rule: " + presentation.RuleId + Environment.NewLine +
                "Category: " + presentation.Category + Environment.NewLine +
                "Source: " + presentation.SourceSummary + Environment.NewLine +
                remoteHeaderLines +
                "MaintenanceContext: " + alert.MaintenanceContext + Environment.NewLine +
                "Severity: " + alert.Severity + Environment.NewLine +
                "Score: " + alert.Score.ToString(CultureInfo.InvariantCulture) + Environment.NewLine +
                "UTC: " + UtcTimestamp.Format(alert.TimestampUtc) + Environment.NewLine +
                "SystemLocalTime: " + alert.SystemLocalTime + Environment.NewLine + Environment.NewLine +
                BuildScoreContextPlainText() + Environment.NewLine +
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
            return TextFormatting.CompactOrEmpty(value, maxLength);
        }

        private static string BuildWhyHtml(Alert alert)
        {
            if (alert.Why == null || alert.Why.Count == 0) return "";

            string html = "<h3>Why This Alerted</h3><ul style=\"margin:6px 0 12px 20px;padding:0;\">";
            foreach (string reason in alert.Why)
            {
                html += "<li style=\"margin:6px 0;" + WrapStyle + "\">" + HtmlEscape(reason) + "</li>";
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

        private static string BeginEmailHtml()
        {
            string width = EmailContentWidthPixels.ToString(CultureInfo.InvariantCulture);
            return "<!doctype html><html><head>" +
                "<meta name=\"color-scheme\" content=\"light dark\">" +
                "<meta name=\"supported-color-schemes\" content=\"light dark\">" +
                "</head><body style=\"margin:0;padding:0;font-family:Arial,sans-serif;line-height:1.45;background:#ffffff;\">" +
                "<table role=\"presentation\" width=\"100%\" cellspacing=\"0\" cellpadding=\"0\" style=\"border-collapse:collapse;width:100%;background:#ffffff;\">" +
                "<tr><td align=\"center\" style=\"padding:20px 12px;\">" +
                "<table role=\"presentation\" align=\"center\" width=\"" + width + "\" cellspacing=\"0\" cellpadding=\"0\" style=\"border-collapse:collapse;width:100%;max-width:" + width + "px;table-layout:fixed;\">" +
                "<tr><td style=\"padding:0;font-family:Arial,sans-serif;font-size:16px;line-height:1.45;" + WrapStyle + "\">";
        }

        private static string EndEmailHtml()
        {
            return "</td></tr></table></td></tr></table></body></html>";
        }

        private static string BuildAlertFieldHtml(string label, string value)
        {
            return "<p style=\"margin:6px 0;" + WrapStyle + "\"><strong>" +
                HtmlEscape(label) + ":</strong> " + HtmlEscape(value) + "</p>";
        }

        private static string BuildOptionalAlertFieldHtml(string label, string value)
        {
            return String.IsNullOrWhiteSpace(value) ? "" : BuildAlertFieldHtml(label, value);
        }

        private static string BuildWrappedPreHtml(string value)
        {
            return "<pre style=\"display:block;box-sizing:border-box;width:100%;max-width:100%;white-space:pre-wrap;" +
                WrapStyle +
                "font-family:Consolas,Monaco,monospace;font-size:13px;line-height:1.4;border:1px solid #999;padding:8px;margin:6px 0 14px 0;\">" +
                HtmlEscape(value) + "</pre>";
        }

        private static string BuildRemoteHeaderFieldsHtml(RemoteEndpointPresentation metadata)
        {
            if (metadata == null || !metadata.HasAny) return "";

            return BuildOptionalAlertFieldHtml("Remote Endpoint", metadata.Endpoint) +
                BuildOptionalAlertFieldHtml("Remote Country", metadata.Country) +
                BuildOptionalAlertFieldHtml("Remote Company", metadata.Company) +
                BuildOptionalAlertFieldHtml("Remote ASN", metadata.Asn) +
                BuildOptionalAlertFieldHtml("Remote Domain", metadata.Domain) +
                BuildOptionalAlertFieldHtml("Remote Enrichment", metadata.Enrichment);
        }

        private static string BuildRemoteHeaderFieldsPlainText(RemoteEndpointPresentation metadata)
        {
            if (metadata == null || !metadata.HasAny) return "";

            string text = "";
            AppendOptionalPlainTextField(ref text, "RemoteEndpoint", metadata.Endpoint);
            AppendOptionalPlainTextField(ref text, "RemoteCountry", metadata.Country);
            AppendOptionalPlainTextField(ref text, "RemoteCompany", metadata.Company);
            AppendOptionalPlainTextField(ref text, "RemoteASN", metadata.Asn);
            AppendOptionalPlainTextField(ref text, "RemoteDomain", metadata.Domain);
            AppendOptionalPlainTextField(ref text, "RemoteEnrichment", metadata.Enrichment);
            return text;
        }

        private static void AppendOptionalPlainTextField(ref string text, string label, string value)
        {
            if (String.IsNullOrWhiteSpace(label) || String.IsNullOrWhiteSpace(value)) return;
            text += label + ": " + value + Environment.NewLine;
        }

        private static bool IsDailySummary(string ruleId)
        {
            return AlertRuleTaxonomy.IsDailySummaryRule(ruleId);
        }

        private static string BuildDailyReportHtml(Alert alert)
        {
            string[] lines = NullToEmpty(alert.Body).Replace("\r\n", "\n").Replace('\r', '\n').Split('\n');
            string html = BeginEmailHtml();
            bool inList = false;
            bool skippedDuplicateTitle = false;

            for (int lineIndex = 0; lineIndex < lines.Length; lineIndex++)
            {
                string raw = lines[lineIndex];
                string line = raw.TrimEnd();
                if (line.Length == 0)
                {
                    if (inList)
                    {
                        html += "</ul>";
                        inList = false;
                    }

                    continue;
                }

                if (IsMarkdownTableStart(lines, lineIndex))
                {
                    if (inList)
                    {
                        html += "</ul>";
                        inList = false;
                    }

                    html += BuildMarkdownTableHtml(lines, ref lineIndex);
                    continue;
                }

                if (line.StartsWith("## ", StringComparison.Ordinal))
                {
                    string heading = line.Substring(3).Trim();
                    if (!skippedDuplicateTitle &&
                        heading.Equals("Daily Arcane EDR Report", StringComparison.OrdinalIgnoreCase))
                    {
                        skippedDuplicateTitle = true;
                        continue;
                    }

                    if (inList)
                    {
                        html += "</ul>";
                        inList = false;
                    }

                    html += "<h2 style=\"font-size:18px;line-height:1.3;margin:20px 0 8px 0;border-top:1px solid #999;padding-top:12px;font-weight:700;\">" +
                        HtmlEscape(heading) + "</h2>";
                    continue;
                }

                if (line.StartsWith("- ", StringComparison.Ordinal))
                {
                    if (!inList)
                    {
                        html += "<ul style=\"margin:6px 0 12px 20px;padding:0;\">";
                        inList = true;
                    }

                    html += "<li style=\"margin:6px 0;" + WrapStyle + "\">" + HtmlEscape(line.Substring(2)) + "</li>";
                    continue;
                }

                if (inList)
                {
                    html += "</ul>";
                    inList = false;
                }

                html += BuildDailyReportLineHtml(line);
            }

            if (inList)
            {
                html += "</ul>";
            }

            html += BuildScoreContextHtml();

            return html + EndEmailHtml();
        }

        private static string BuildScoreContextHtml()
        {
            string tableStyle = "border-collapse:collapse;table-layout:fixed;width:100%;max-width:100%;margin:8px 0 14px 0;font-family:Arial,sans-serif;font-size:14px;line-height:1.35;";
            string thStyle = "border:1px solid #999;padding:6px 8px;text-align:left;font-weight:700;vertical-align:top;width:22%;word-break:normal;overflow-wrap:anywhere;";
            string tdStyle = "border:1px solid #999;padding:6px 8px;text-align:left;vertical-align:top;" + WrapStyle + "width:78%;";
            return "<h2 style=\"font-size:18px;line-height:1.3;margin:20px 0 8px 0;border-top:1px solid #999;padding-top:12px;font-weight:700;\">Score Context</h2>" +
                "<p style=\"margin:6px 0;\">Scores are Arcane risk and review-priority signals, not proof of compromise. Corroborating source context still matters.</p>" +
                "<table role=\"presentation\" width=\"100%\" cellspacing=\"0\" cellpadding=\"0\" style=\"" + tableStyle + "\">" +
                "<colgroup><col width=\"22%\" style=\"width:22%;\"><col width=\"78%\" style=\"width:78%;\"></colgroup>" +
                "<thead><tr><th width=\"22%\" style=\"" + thStyle + "\">Score</th><th width=\"78%\" style=\"" + tdStyle + "font-weight:700;\">Meaning</th></tr></thead>" +
                "<tbody>" +
                "<tr><td width=\"22%\" style=\"" + thStyle + "\">0-49</td><td width=\"78%\" style=\"" + tdStyle + "\">Low-priority context. Usually useful for baseline and tuning unless paired with stronger evidence.</td></tr>" +
                "<tr><td width=\"22%\" style=\"" + thStyle + "\">50-59</td><td width=\"78%\" style=\"" + tdStyle + "\">Low signal. Review if unexpected, repeated, or close to other suspicious activity.</td></tr>" +
                "<tr><td width=\"22%\" style=\"" + thStyle + "\">60-74</td><td width=\"78%\" style=\"" + tdStyle + "\">Medium signal. Common default notification range; review source context before acting.</td></tr>" +
                "<tr><td width=\"22%\" style=\"" + thStyle + "\">75-89</td><td width=\"78%\" style=\"" + tdStyle + "\">High signal. Review promptly and correlate with process lineage, user action, destination, or persistence context.</td></tr>" +
                "<tr><td width=\"22%\" style=\"" + thStyle + "\">90-100</td><td width=\"78%\" style=\"" + tdStyle + "\">Critical priority. Treat as urgent review material, but confirm context before declaring compromise.</td></tr>" +
                "</tbody></table>";
        }

        private static string BuildScoreContextPlainText()
        {
            return "Score Context" + Environment.NewLine +
                "Scores are Arcane risk and review-priority signals, not proof of compromise. Corroborating source context still matters." + Environment.NewLine +
                "0-49: Low-priority context; usually baseline/tuning unless paired with stronger evidence." + Environment.NewLine +
                "50-59: Low signal; review if unexpected, repeated, or close to other suspicious activity." + Environment.NewLine +
                "60-74: Medium signal; common default notification range; review source context before acting." + Environment.NewLine +
                "75-89: High signal; review promptly and correlate with lineage, user action, destination, or persistence." + Environment.NewLine +
                "90-100: Critical priority; urgent review material, but confirm context before declaring compromise." + Environment.NewLine;
        }

        private static string BuildDailyReportLineHtml(string line)
        {
            string escaped = HtmlEscape(line);
            int separator = line.IndexOf(':');
            if (separator > 0 && separator <= 32)
            {
                string key = HtmlEscape(line.Substring(0, separator + 1));
                string value = HtmlEscape(line.Substring(separator + 1).TrimStart());
                return "<p style=\"margin:6px 0;" + WrapStyle + "\"><strong>" + key + "</strong> " + value + "</p>";
            }

            return "<p style=\"margin:6px 0;" + WrapStyle + "\">" + escaped + "</p>";
        }

        private static bool IsMarkdownTableStart(string[] lines, int index)
        {
            if (index < 0 || index + 1 >= lines.Length) return false;
            string header = lines[index].Trim();
            string separator = lines[index + 1].Trim();
            return IsMarkdownTableLine(header) && IsMarkdownTableSeparator(separator);
        }

        private static bool IsMarkdownTableLine(string line)
        {
            if (String.IsNullOrWhiteSpace(line)) return false;
            string trimmed = line.Trim();
            return trimmed.StartsWith("|", StringComparison.Ordinal) &&
                trimmed.EndsWith("|", StringComparison.Ordinal) &&
                trimmed.IndexOf('|', 1) > 0;
        }

        private static bool IsMarkdownTableSeparator(string line)
        {
            if (!IsMarkdownTableLine(line)) return false;
            string value = line.Replace("|", "").Trim();
            if (value.Length == 0 || value.IndexOf('-') < 0) return false;
            foreach (char ch in value)
            {
                if (ch != '-' && ch != ':' && ch != ' ') return false;
            }

            return true;
        }

        private static string BuildMarkdownTableHtml(string[] lines, ref int index)
        {
            List<string> header = SplitMarkdownTableRow(lines[index]);
            string tableStyle = "border-collapse:collapse;table-layout:fixed;width:100%;max-width:100%;margin:8px 0 14px 0;font-family:Arial,sans-serif;font-size:14px;line-height:1.35;";
            string thStyle = "border:1px solid #999;padding:6px 8px;text-align:left;font-weight:700;vertical-align:top;" + WrapStyle;
            string tdStyle = "border:1px solid #999;padding:6px 8px;text-align:left;vertical-align:top;" + WrapStyle;
            string labelCellStyle = tdStyle + "white-space:normal;";
            string html = "<table role=\"presentation\" width=\"100%\" cellspacing=\"0\" cellpadding=\"0\" style=\"" + tableStyle + "\">" +
                BuildColumnGroupHtml(header) +
                "<thead><tr>";
            for (int cellIndex = 0; cellIndex < header.Count; cellIndex++)
            {
                html += "<th" + CellWidthAttribute(header, cellIndex) + " style=\"" +
                    HeaderCellStyle(header, cellIndex, thStyle) + "\">" + HtmlEscape(header[cellIndex]) + "</th>";
            }

            html += "</tr></thead><tbody>";
            index += 2;
            for (; index < lines.Length; index++)
            {
                string line = lines[index].Trim();
                if (!IsMarkdownTableLine(line) || IsMarkdownTableSeparator(line))
                {
                    index--;
                    break;
                }

                List<string> cells = SplitMarkdownTableRow(line);
                html += "<tr>";
                for (int cellIndex = 0; cellIndex < header.Count; cellIndex++)
                {
                    string cell = cellIndex < cells.Count ? cells[cellIndex] : "";
                    string style = BodyCellStyle(header, cellIndex, tdStyle, labelCellStyle);
                    html += "<td" + CellWidthAttribute(header, cellIndex) + " style=\"" +
                        style + "\">" + HtmlEscape(cell) + "</td>";
                }

                html += "</tr>";
            }

            return html + "</tbody></table>";
        }

        private static string BuildColumnGroupHtml(List<string> header)
        {
            int[] widths = ColumnWidths(header);
            if (widths == null || widths.Length == 0) return "";

            string html = "<colgroup>";
            for (int index = 0; index < widths.Length; index++)
            {
                string width = widths[index].ToString(CultureInfo.InvariantCulture) + "%";
                html += "<col width=\"" + width + "\" style=\"width:" + width + ";\">";
            }

            return html + "</colgroup>";
        }

        private static string CellWidthAttribute(List<string> header, int cellIndex)
        {
            int[] widths = ColumnWidths(header);
            if (widths == null || cellIndex < 0 || cellIndex >= widths.Length) return "";

            return " width=\"" + widths[cellIndex].ToString(CultureInfo.InvariantCulture) + "%\"";
        }

        private static int[] ColumnWidths(List<string> header)
        {
            if (header == null || header.Count == 0) return null;

            if (header.Count == 2 &&
                (EqualsHeader(header[0], "Field") || EqualsHeader(header[0], "Item") || EqualsHeader(header[0], "Question") || EqualsHeader(header[0], "Note")) &&
                (EqualsHeader(header[1], "Value") || EqualsHeader(header[1], "Answer") || EqualsHeader(header[1], "Why it matters")))
            {
                return new[] { 28, 72 };
            }

            if (HasHeader(header, "Process / source") && HasHeader(header, "Assessment") && header.Count == 6)
            {
                return new[] { 18, 18, 18, 8, 8, 30 };
            }

            if (header.Count == 4 && HasHeader(header, "Context"))
            {
                return new[] { 42, 12, 14, 32 };
            }

            if (header.Count == 3 && HasHeader(header, "How to read it"))
            {
                return new[] { 22, 22, 56 };
            }

            return null;
        }

        private static string HeaderCellStyle(List<string> header, int cellIndex, string baseStyle)
        {
            string style = baseStyle + CellWidthStyle(header, cellIndex);
            if (cellIndex == 0 && IsLabelValueTable(header)) return style + "word-break:normal;";
            return style;
        }

        private static string BodyCellStyle(List<string> header, int cellIndex, string baseStyle, string labelStyle)
        {
            string style = (cellIndex == 0 && IsLabelValueTable(header)) ? labelStyle : baseStyle;
            style += CellWidthStyle(header, cellIndex);
            if (IsCountOrScoreColumn(header, cellIndex)) return style + "white-space:nowrap;";
            return style;
        }

        private static string CellWidthStyle(List<string> header, int cellIndex)
        {
            int[] widths = ColumnWidths(header);
            if (widths == null || cellIndex < 0 || cellIndex >= widths.Length) return "";

            return "width:" + widths[cellIndex].ToString(CultureInfo.InvariantCulture) + "%;";
        }

        private static bool IsLabelValueTable(List<string> header)
        {
            int[] widths = ColumnWidths(header);
            return header != null && header.Count == 2 && widths != null && widths.Length == 2;
        }

        private static bool IsCountOrScoreColumn(List<string> header, int cellIndex)
        {
            if (header == null || cellIndex < 0 || cellIndex >= header.Count) return false;
            return EqualsHeader(header[cellIndex], "Count") ||
                EqualsHeader(header[cellIndex], "Score") ||
                EqualsHeader(header[cellIndex], "Max score") ||
                EqualsHeader(header[cellIndex], "Cautious score");
        }

        private static bool HasHeader(List<string> header, string value)
        {
            if (header == null) return false;
            foreach (string cell in header)
            {
                if (EqualsHeader(cell, value)) return true;
            }

            return false;
        }

        private static bool EqualsHeader(string left, string right)
        {
            return left != null && left.Equals(right, StringComparison.OrdinalIgnoreCase);
        }

        private static List<string> SplitMarkdownTableRow(string line)
        {
            string value = line.Trim();
            if (value.StartsWith("|", StringComparison.Ordinal)) value = value.Substring(1);
            if (value.EndsWith("|", StringComparison.Ordinal)) value = value.Substring(0, value.Length - 1);

            string[] parts = value.Split('|');
            List<string> cells = new List<string>();
            foreach (string part in parts)
            {
                cells.Add(part.Trim());
            }

            return cells;
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
