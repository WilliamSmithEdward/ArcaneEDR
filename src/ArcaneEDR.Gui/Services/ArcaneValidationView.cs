using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

namespace ArcaneEDR_Gui.Services;

internal sealed class ArcaneValidationMessage
{
    [JsonPropertyName("level")]
    public string Level { get; set; } = "";

    [JsonPropertyName("message")]
    public string Message { get; set; } = "";
}

internal sealed class ArcaneValidationReport
{
    [JsonPropertyName("ok")]
    public bool Ok { get; set; }

    [JsonPropertyName("error_count")]
    public int ErrorCount { get; set; }

    [JsonPropertyName("warning_count")]
    public int WarningCount { get; set; }

    [JsonPropertyName("summary")]
    public string Summary { get; set; } = "";

    [JsonPropertyName("config_path")]
    public string ConfigPath { get; set; } = "";

    [JsonPropertyName("log_directory")]
    public string LogDirectory { get; set; } = "";

    [JsonPropertyName("messages")]
    public List<ArcaneValidationMessage> Messages { get; set; } = new List<ArcaneValidationMessage>();

    public string RawText { get; set; } = "";
}

internal static class ArcaneValidationView
{
    private static readonly Regex SummaryRegex = new Regex(
        @"Validation summary:\s*(?<errors>\d+)\s+error\(s\),\s*(?<warnings>\d+)\s+warning\(s\)\.",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);

    public static async Task<ArcaneValidationReport> RunAsync()
    {
        ArcaneCommandResult result = await ArcaneCommandRunner.RunAsync("--validate-config", "--json");
        string text = result.CombinedText();
        ArcaneValidationReport? report = TryParseJson(text);
        if (report != null)
        {
            report.RawText = text;
            return report;
        }

        return FromHumanText(text);
    }

    public static string Heading(ArcaneValidationReport report)
    {
        if (report.ErrorCount > 0) return "Configuration blockers";
        if (report.WarningCount > 0) return "Configuration warnings";
        return "Configuration validation";
    }

    public static string Heading(string validationText)
    {
        if (HasErrors(validationText)) return "Configuration blockers";
        if (HasWarnings(validationText)) return "Configuration warnings";
        return "Configuration validation";
    }

    public static string BuildOverviewText(ArcaneValidationReport report)
    {
        List<string> failures = report.Messages
            .Where(message => message.Level.Equals("fail", StringComparison.OrdinalIgnoreCase))
            .Select(message => "[FAIL] " + message.Message)
            .ToList();
        List<string> warnings = report.Messages
            .Where(message => message.Level.Equals("warn", StringComparison.OrdinalIgnoreCase))
            .Select(message => "[WARN] " + message.Message)
            .ToList();

        if (failures.Count == 0 && warnings.Count == 0)
        {
            return String.IsNullOrWhiteSpace(report.Summary)
                ? "No validation blockers reported."
                : "No validation blockers reported." + Environment.NewLine + report.Summary;
        }

        List<string> lines = new List<string>();
        if (failures.Count == 0)
        {
            lines.Add("No configuration blockers found.");
        }

        lines.AddRange(failures);
        lines.AddRange(warnings);

        if (!String.IsNullOrWhiteSpace(report.Summary))
        {
            lines.Add(report.Summary);
        }

        if (failures.Count == 0 && HasEventLogAccessWarning(warnings))
        {
            lines.Add("These event-log warnings are expected when the GUI validates from a standard user context. Use Maintenance > Validate Admin to verify elevated service telemetry access.");
        }

        return String.Join(Environment.NewLine, lines);
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

    public static string? FirstFailureLine(ArcaneValidationReport report)
    {
        ArcaneValidationMessage? failure = report.Messages.FirstOrDefault(message =>
            message.Level.Equals("fail", StringComparison.OrdinalIgnoreCase));
        return failure == null ? null : "[FAIL] " + failure.Message;
    }

    private static ArcaneValidationReport? TryParseJson(string text)
    {
        string trimmed = text.Trim();
        if (!trimmed.StartsWith("{", StringComparison.Ordinal)) return null;

        try
        {
            return JsonSerializer.Deserialize<ArcaneValidationReport>(trimmed, new JsonSerializerOptions
            {
                PropertyNameCaseInsensitive = true
            });
        }
        catch
        {
            return null;
        }
    }

    private static ArcaneValidationReport FromHumanText(string validationText)
    {
        ArcaneValidationReport report = new ArcaneValidationReport
        {
            Ok = !HasErrors(validationText),
            RawText = validationText
        };

        if (TryParseSummary(validationText, out int errors, out int warnings))
        {
            report.ErrorCount = errors;
            report.WarningCount = warnings;
            report.Summary = SummaryLine(validationText);
        }

        foreach (string line in Lines(validationText))
        {
            string trimmed = line.Trim();
            if (trimmed.StartsWith("[PASS]", StringComparison.OrdinalIgnoreCase))
            {
                report.Messages.Add(new ArcaneValidationMessage { Level = "pass", Message = trimmed.Substring(6).Trim() });
            }
            else if (trimmed.StartsWith("[WARN]", StringComparison.OrdinalIgnoreCase))
            {
                report.Messages.Add(new ArcaneValidationMessage { Level = "warn", Message = trimmed.Substring(6).Trim() });
            }
            else if (trimmed.StartsWith("[FAIL]", StringComparison.OrdinalIgnoreCase))
            {
                report.Messages.Add(new ArcaneValidationMessage { Level = "fail", Message = trimmed.Substring(6).Trim() });
            }
        }

        if (report.ErrorCount == 0)
        {
            report.ErrorCount = report.Messages.Count(message => message.Level.Equals("fail", StringComparison.OrdinalIgnoreCase));
        }

        if (report.WarningCount == 0)
        {
            report.WarningCount = report.Messages.Count(message => message.Level.Equals("warn", StringComparison.OrdinalIgnoreCase));
        }

        return report;
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
