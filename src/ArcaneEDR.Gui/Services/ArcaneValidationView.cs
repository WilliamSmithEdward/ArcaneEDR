using System;
using System.Collections.Generic;
using System.Text.RegularExpressions;

namespace ArcaneEDR_Gui.Services;

internal static class ArcaneValidationView
{
    private static readonly Regex SummaryRegex = new Regex(
        @"Validation summary:\s*(?<errors>\d+)\s+error\(s\),\s*(?<warnings>\d+)\s+warning\(s\)\.",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);

    public static string Heading(string validationText)
    {
        if (HasErrors(validationText)) return "Configuration blockers";
        if (HasWarnings(validationText)) return "Configuration warnings";
        return "Configuration validation";
    }

    public static string BuildOverviewText(string validationText)
    {
        List<string> failures = MatchingLines(validationText, "[FAIL]");
        List<string> warnings = MatchingLines(validationText, "[WARN]");
        string summary = SummaryLine(validationText);

        if (failures.Count == 0 && warnings.Count == 0)
        {
            return String.IsNullOrWhiteSpace(summary)
                ? "No validation blockers reported."
                : "No validation blockers reported." + Environment.NewLine + summary;
        }

        List<string> lines = new List<string>();
        if (failures.Count == 0)
        {
            lines.Add("No configuration blockers found.");
        }

        lines.AddRange(failures);
        lines.AddRange(warnings);

        if (!String.IsNullOrWhiteSpace(summary))
        {
            lines.Add(summary);
        }

        if (failures.Count == 0 && HasEventLogAccessWarning(warnings))
        {
            lines.Add("These event-log warnings are expected when the GUI validates from a standard user context. Use Maintenance > Validate Admin to verify elevated service telemetry access.");
        }

        return String.Join(Environment.NewLine, lines);
    }

    public static bool HasErrors(string validationText)
    {
        if (TryParseSummary(validationText, out int errors, out _))
        {
            return errors > 0;
        }

        return validationText.IndexOf("[FAIL]", StringComparison.OrdinalIgnoreCase) >= 0;
    }

    public static bool HasWarnings(string validationText)
    {
        if (TryParseSummary(validationText, out _, out int warnings))
        {
            return warnings > 0;
        }

        return validationText.IndexOf("[WARN]", StringComparison.OrdinalIgnoreCase) >= 0;
    }

    public static string? FirstFailureLine(string validationText)
    {
        foreach (string line in Lines(validationText))
        {
            if (line.IndexOf("[FAIL]", StringComparison.OrdinalIgnoreCase) >= 0)
            {
                return line.Trim();
            }
        }

        return null;
    }

    private static bool TryParseSummary(string validationText, out int errors, out int warnings)
    {
        errors = 0;
        warnings = 0;

        Match match = SummaryRegex.Match(validationText);
        if (!match.Success) return false;

        return Int32.TryParse(match.Groups["errors"].Value, out errors) &&
            Int32.TryParse(match.Groups["warnings"].Value, out warnings);
    }

    private static string SummaryLine(string validationText)
    {
        foreach (string line in Lines(validationText))
        {
            if (line.TrimStart().StartsWith("Validation summary:", StringComparison.OrdinalIgnoreCase))
            {
                return line.Trim();
            }
        }

        return "";
    }

    private static List<string> MatchingLines(string validationText, string token)
    {
        List<string> lines = new List<string>();
        foreach (string line in Lines(validationText))
        {
            if (line.IndexOf(token, StringComparison.OrdinalIgnoreCase) >= 0)
            {
                lines.Add(line.Trim());
            }
        }

        return lines;
    }

    private static bool HasEventLogAccessWarning(IReadOnlyList<string> warnings)
    {
        foreach (string warning in warnings)
        {
            if (warning.IndexOf("Event log not readable", StringComparison.OrdinalIgnoreCase) >= 0)
            {
                return true;
            }
        }

        return false;
    }

    private static string[] Lines(string text)
    {
        return text.Split(new[] { "\r\n", "\n" }, StringSplitOptions.None);
    }
}
