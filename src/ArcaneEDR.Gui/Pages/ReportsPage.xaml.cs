using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using ArcaneEDR_Gui.Services;

namespace ArcaneEDR_Gui.Pages;

public sealed partial class ReportsPage : Page
{
    public ReportsPage()
    {
        InitializeComponent();
        Loaded += async (_, _) => await PreviewAsync(false);
    }

    private async void Preview_Click(object sender, RoutedEventArgs e)
    {
        await PreviewAsync(false, sender as Button);
    }

    private async void Json_Click(object sender, RoutedEventArgs e)
    {
        await PreviewAsync(true, sender as Button);
    }

    private async void Send_Click(object sender, RoutedEventArgs e)
    {
        if (!await GuiHelp.ConfirmRiskAsync(
            XamlRoot,
            "Send a live daily report?",
            "This uses the currently configured notification provider and recipients. It may send a real email, webhook, local JSONL notification, or Windows Event Log record depending on config.\n\n" +
            "Preview first when changing report content, recipients, provider settings, or enrichment behavior.",
            "Send report"))
        {
            ReportOutputText.Text = "Send canceled. No live report was requested.";
            return;
        }

        await GuiCommandStatus.RunAsync(sender as Button, ReportOutputText, "Sending daily report...", async () =>
        {
            ArcaneCommandResult result = await ArcaneCommandRunner.RunAsync(TimeSpan.FromMinutes(2), "--test-daily-report");
            return result.CombinedText();
        });
    }

    private async void Help_Click(object sender, RoutedEventArgs e)
    {
        await GuiHelp.ShowAsync(
            XamlRoot,
            "Reports help",
            "Preview shows the daily report without sending it. JSON shows the structured report payload for validation and troubleshooting.\n\n" +
            "Send requests a live daily report through the configured provider, so it can reach real recipients. Use Preview before Send after config, policy, enrichment, or recipient changes.\n\n" +
            "Daily reports should not be blocked by ordinary alert burst limits; validation output can help confirm provider and rate-limit state.");
    }

    private async System.Threading.Tasks.Task PreviewAsync(bool json, Button? button = null)
    {
        await GuiCommandStatus.RunAsync(button, ReportOutputText, json ? "Loading report JSON..." : "Loading report preview...", async () =>
        {
            ArcaneCommandResult result = json
                ? await ArcaneCommandRunner.RunAsync("--preview-daily-report", "--json")
                : await ArcaneCommandRunner.RunAsync("--preview-daily-report");
            string output = result.CombinedText();
            return json ? output : RenderReportPreview(output);
        });
    }

    private static string RenderReportPreview(string text)
    {
        if (String.IsNullOrWhiteSpace(text))
        {
            return "No report preview was returned.";
        }

        StringBuilder rendered = new StringBuilder();
        List<string> tableLines = new List<string>();

        foreach (string originalLine in text.Replace("\r\n", "\n").Replace('\r', '\n').Split('\n'))
        {
            string line = originalLine.TrimEnd();
            if (IsTableLine(line))
            {
                tableLines.Add(line);
                continue;
            }

            FlushTable(tableLines, rendered);
            string trimmed = line.Trim();
            if (String.IsNullOrWhiteSpace(trimmed))
            {
                AppendBlank(rendered);
                continue;
            }

            if (trimmed.StartsWith("#", StringComparison.Ordinal))
            {
                AppendSection(rendered, trimmed.TrimStart('#').Trim());
                continue;
            }

            rendered.AppendLine(CleanMarkdownInline(trimmed));
        }

        FlushTable(tableLines, rendered);
        return rendered.ToString().Trim();
    }

    private static void FlushTable(List<string> tableLines, StringBuilder rendered)
    {
        if (tableLines.Count == 0)
        {
            return;
        }

        List<List<string>> rows = tableLines
            .Select(ParseTableRow)
            .Where(row => row.Count > 0 && !IsSeparatorRow(row))
            .ToList();
        tableLines.Clear();
        if (rows.Count == 0)
        {
            return;
        }

        List<string> header = rows[0];
        foreach (List<string> row in rows.Skip(1))
        {
            if (row.Count == 2)
            {
                rendered.AppendLine(row[0] + ": " + CleanMarkdownInline(row[1]));
                continue;
            }

            List<string> parts = new List<string>();
            int count = Math.Min(header.Count, row.Count);
            for (int index = 0; index < count; index++)
            {
                string label = CleanMarkdownInline(header[index]);
                string value = CleanMarkdownInline(row[index]);
                if (!String.IsNullOrWhiteSpace(value))
                {
                    parts.Add(String.IsNullOrWhiteSpace(label) ? value : label + ": " + value);
                }
            }

            if (parts.Count > 0)
            {
                rendered.AppendLine("- " + String.Join("; ", parts));
            }
        }

        AppendBlank(rendered);
    }

    private static bool IsTableLine(string line)
    {
        string trimmed = line.Trim();
        return trimmed.StartsWith("|", StringComparison.Ordinal) && trimmed.Count(ch => ch == '|') >= 2;
    }

    private static List<string> ParseTableRow(string line)
    {
        string trimmed = line.Trim().Trim('|');
        return trimmed
            .Split('|')
            .Select(cell => CleanMarkdownInline(cell.Trim()))
            .ToList();
    }

    private static bool IsSeparatorRow(List<string> row)
    {
        return row.Count > 0 && row.All(cell =>
            cell.Length > 0 &&
            cell.All(ch => ch == '-' || ch == ':' || Char.IsWhiteSpace(ch)));
    }

    private static void AppendSection(StringBuilder rendered, string title)
    {
        AppendBlank(rendered);
        rendered.AppendLine(title);
        AppendBlank(rendered);
    }

    private static void AppendBlank(StringBuilder rendered)
    {
        if (rendered.Length == 0)
        {
            return;
        }

        string current = rendered.ToString();
        if (!current.EndsWith(Environment.NewLine + Environment.NewLine, StringComparison.Ordinal))
        {
            rendered.AppendLine();
        }
    }

    private static string CleanMarkdownInline(string text)
    {
        return text
            .Replace("**", "", StringComparison.Ordinal)
            .Replace("`", "", StringComparison.Ordinal)
            .Trim();
    }
}
