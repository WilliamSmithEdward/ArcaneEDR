using System;
using System.Collections.Generic;
using System.Linq;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using ArcaneEDR_Gui.Services;

namespace ArcaneEDR_Gui.Pages;

public sealed partial class AlertsPage : Page
{
    private List<ArcaneAlertRecord> allAlerts = new List<ArcaneAlertRecord>();
    private double externalThreshold = 60;
    private bool loaded;

    public AlertsPage()
    {
        InitializeComponent();
        Loaded += async (_, _) =>
        {
            loaded = true;
            await RefreshAsync();
        };
    }

    private async void Refresh_Click(object sender, RoutedEventArgs e)
    {
        await RefreshAsync();
    }

    private void OpenLogs_Click(object sender, RoutedEventArgs e)
    {
        ArcaneScriptRunner.OpenPath(ArcanePaths.Discover().LogDirectory);
    }

    private void Filter_Changed(object sender, RoutedEventArgs e)
    {
        if (!loaded) return;
        ApplyFilters();
    }

    private void SearchBox_TextChanged(object sender, TextChangedEventArgs e)
    {
        if (!loaded) return;
        ApplyFilters();
    }

    private void AlertsList_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        SelectedAlertText.Text = AlertsList.SelectedItem is ArcaneAlertRecord alert
            ? BuildSelectedAlertText(alert)
            : "Select an alert to inspect its local evidence.";
    }

    private async System.Threading.Tasks.Task RefreshAsync()
    {
        ArcaneConfigBundle config = ArcaneConfigBundle.Load();
        externalThreshold = config.Runtime.GetNumber("MinimumEmailScore", 60);
        AlertConfigContextText.Text =
            "ExternalAlertProvider=" + config.Runtime.Get("ExternalAlertProvider", "Disabled") + Environment.NewLine +
            "MinimumEmailScore=" + externalThreshold + Environment.NewLine +
            "BaselineLearningMode=" + config.Runtime.Get("BaselineLearningMode", "false") + Environment.NewLine +
            "EnableExternalAlertGrouping=" + config.Runtime.Get("EnableExternalAlertGrouping", "false") + Environment.NewLine +
            "RuleMinimumEmailScores=" + config.Runtime.Get("RuleMinimumEmailScores", "");

        string lookback = SelectedLookback();
        ArcaneCommandResult result = await ArcaneCommandRunner.RunAsync("--alert-volume", "--last", lookback.Equals("All", StringComparison.OrdinalIgnoreCase) ? "7d" : lookback);
        VolumeText.Text = result.CombinedText();
        RecentAlertsText.Text = ArcaneStateReader.ReadRecentAlerts(80);

        allAlerts = ArcaneAlertStore.ReadAlerts(5000);
        PopulateCategories();
        ApplyFilters();
    }

    private void PopulateCategories()
    {
        string selected = ComboText(CategoryBox, "Any");
        CategoryBox.Items.Clear();
        CategoryBox.Items.Add(new ComboBoxItem { Content = "Any" });

        foreach (string category in allAlerts
            .Select(alert => alert.Category)
            .Where(category => !String.IsNullOrWhiteSpace(category))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .OrderBy(category => category))
        {
            CategoryBox.Items.Add(new ComboBoxItem { Content = category });
        }

        CategoryBox.SelectedIndex = 0;
        for (int index = 0; index < CategoryBox.Items.Count; index++)
        {
            if (CategoryBox.Items[index] is ComboBoxItem item &&
                selected.Equals(item.Content?.ToString(), StringComparison.OrdinalIgnoreCase))
            {
                CategoryBox.SelectedIndex = index;
                break;
            }
        }
    }

    private void ApplyFilters()
    {
        IEnumerable<ArcaneAlertRecord> filtered = allAlerts;
        DateTime cutoff = LookbackCutoff();
        if (cutoff > DateTime.MinValue)
        {
            filtered = filtered.Where(alert => alert.TimestampUtc >= cutoff);
        }

        string severity = ComboText(SeverityBox, "Any");
        if (!severity.Equals("Any", StringComparison.OrdinalIgnoreCase))
        {
            filtered = filtered.Where(alert => SeverityMatches(alert, severity));
        }

        string category = ComboText(CategoryBox, "Any");
        if (!category.Equals("Any", StringComparison.OrdinalIgnoreCase))
        {
            filtered = filtered.Where(alert => alert.Category.Equals(category, StringComparison.OrdinalIgnoreCase));
        }

        if (ExternalCandidatesBox.IsChecked == true)
        {
            filtered = filtered.Where(alert => alert.Score >= externalThreshold);
        }

        string search = SearchBox.Text.Trim();
        if (!String.IsNullOrWhiteSpace(search))
        {
            filtered = filtered.Where(alert => MatchesSearch(alert, search));
        }

        List<ArcaneAlertRecord> rows = Sort(filtered).Take(1000).ToList();
        AlertsList.ItemsSource = rows;
        TableSummaryText.Text = rows.Count + " visible of " + allAlerts.Count +
            " loaded rows. External threshold filter uses MinimumEmailScore=" + externalThreshold + ".";
        SelectedAlertText.Text = rows.Count == 0
            ? "No alerts match the current filters."
            : BuildSelectedAlertText(rows[0]);
        AlertsList.SelectedIndex = rows.Count == 0 ? -1 : 0;
    }

    private IEnumerable<ArcaneAlertRecord> Sort(IEnumerable<ArcaneAlertRecord> source)
    {
        string sort = ComboText(SortBox, "Time");
        bool asc = ComboText(SortDirectionBox, "Desc").Equals("Asc", StringComparison.OrdinalIgnoreCase);

        IOrderedEnumerable<ArcaneAlertRecord> ordered = sort switch
        {
            "Score" => asc ? source.OrderBy(alert => alert.Score) : source.OrderByDescending(alert => alert.Score),
            "Rule" => asc ? source.OrderBy(alert => alert.RuleId) : source.OrderByDescending(alert => alert.RuleId),
            "Category" => asc ? source.OrderBy(alert => alert.Category) : source.OrderByDescending(alert => alert.Category),
            "Country" => asc ? source.OrderBy(alert => alert.Country) : source.OrderByDescending(alert => alert.Country),
            "Company" => asc ? source.OrderBy(alert => alert.Company) : source.OrderByDescending(alert => alert.Company),
            _ => asc ? source.OrderBy(alert => alert.TimestampUtc) : source.OrderByDescending(alert => alert.TimestampUtc)
        };

        return ordered.ThenByDescending(alert => alert.Score);
    }

    private DateTime LookbackCutoff()
    {
        string lookback = SelectedLookback();
        return lookback switch
        {
            "10m" => DateTime.UtcNow.AddMinutes(-10),
            "1h" => DateTime.UtcNow.AddHours(-1),
            "24h" => DateTime.UtcNow.AddHours(-24),
            "7d" => DateTime.UtcNow.AddDays(-7),
            _ => DateTime.MinValue
        };
    }

    private string SelectedLookback()
    {
        return ComboText(LookbackBox, "24h");
    }

    private static string ComboText(ComboBox comboBox, string fallback)
    {
        return (comboBox.SelectedItem as ComboBoxItem)?.Content?.ToString() ?? fallback;
    }

    private static bool SeverityMatches(ArcaneAlertRecord alert, string selected)
    {
        if (selected.Equals("Critical", StringComparison.OrdinalIgnoreCase))
        {
            return alert.Score >= 90 || alert.Severity.Equals("critical", StringComparison.OrdinalIgnoreCase);
        }

        if (selected.Equals("High", StringComparison.OrdinalIgnoreCase))
        {
            return alert.Score >= 75 && alert.Score < 90;
        }

        if (selected.Equals("Medium", StringComparison.OrdinalIgnoreCase))
        {
            return alert.Score >= 50 && alert.Score < 75;
        }

        if (selected.Equals("Low", StringComparison.OrdinalIgnoreCase))
        {
            return alert.Score < 50;
        }

        return true;
    }

    private static bool MatchesSearch(ArcaneAlertRecord alert, string search)
    {
        return Contains(alert.RuleId, search) ||
            Contains(alert.Category, search) ||
            Contains(alert.Severity, search) ||
            Contains(alert.Title, search) ||
            Contains(alert.Process, search) ||
            Contains(alert.RemoteIp, search) ||
            Contains(alert.Country, search) ||
            Contains(alert.Company, search) ||
            Contains(alert.PolicyContext, search) ||
            Contains(alert.Entity, search) ||
            Contains(alert.Body, search);
    }

    private static bool Contains(string value, string search)
    {
        return value.IndexOf(search, StringComparison.OrdinalIgnoreCase) >= 0;
    }

    private static string BuildSelectedAlertText(ArcaneAlertRecord alert)
    {
        return "UTC=" + alert.TimestampUtc.ToString("u") + Environment.NewLine +
            "Rule=" + alert.RuleId + " Category=" + alert.Category + " Severity=" + alert.Severity + " Score=" + alert.Score + Environment.NewLine +
            "Process=" + alert.Process + " RemoteIp=" + alert.RemoteIp + " Country=" + alert.Country + " Company=" + alert.Company + Environment.NewLine +
            "Policy=" + alert.PolicyContext + Environment.NewLine +
            "MaintenanceContext=" + alert.MaintenanceContext + " ExternalSuppressed=" + alert.ExternalSuppressedByPolicy + " ExternalForced=" + alert.ExternalForcedByPolicy + Environment.NewLine +
            "Recommendation=" + alert.Recommendation + Environment.NewLine +
            "Entity=" + alert.Entity;
    }
}
