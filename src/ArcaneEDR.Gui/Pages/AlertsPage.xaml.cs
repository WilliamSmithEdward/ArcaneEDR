using System;
using System.Collections.Generic;
using System.Linq;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using ArcaneEDR_Gui.Controls;
using ArcaneEDR_Gui.Services;

namespace ArcaneEDR_Gui.Pages;

public sealed partial class AlertsPage : Page
{
    private List<ArcaneAlertRecord> allAlerts = new List<ArcaneAlertRecord>();
    private double externalThreshold = 60;
    private bool loaded;
    private string sortColumn = "Time";
    private bool sortAscending;

    public AlertsPage()
    {
        InitializeComponent();
        ConfigureResizeHandles();
        UpdateSortIndicators();
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

    private async void Help_Click(object sender, RoutedEventArgs e)
    {
        await GuiHelp.ShowAsync(
            XamlRoot,
            "Alerts help",
            "The Alerts table is local evidence first: filtering or grouping changes what you see in the GUI, not what Arcane preserves in JSONL.\n\n" +
            "Use External threshold to focus on entries that would normally qualify for external notification under the current MinimumEmailScore.\n\n" +
            "Country and company values come from enrichment. Missing company data is not proof of compromise; pair it with process, rule, score, country, and policy context.\n\n" +
            "Raw JSONL is available for exact evidence when you need to copy or inspect the underlying record.");
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
        ShowSelectedAlert(AlertsList.SelectedItem as ArcaneAlertRecord);
    }

    private void SortHeader_Click(object sender, RoutedEventArgs e)
    {
        if (sender is not FrameworkElement element || element.Tag is not string column)
        {
            return;
        }

        if (sortColumn.Equals(column, StringComparison.OrdinalIgnoreCase))
        {
            sortAscending = !sortAscending;
        }
        else
        {
            sortColumn = column;
            sortAscending = DefaultSortAscending(column);
        }

        UpdateSortIndicators();
        ApplyFilters();
    }

    private void ConfigureResizeHandles()
    {
        TimeColumnResizeHandle.ResizeDelta += ColumnResizeHandle_ResizeDelta;
        RuleColumnResizeHandle.ResizeDelta += ColumnResizeHandle_ResizeDelta;
        CategoryColumnResizeHandle.ResizeDelta += ColumnResizeHandle_ResizeDelta;
        ScoreColumnResizeHandle.ResizeDelta += ColumnResizeHandle_ResizeDelta;
        CountryColumnResizeHandle.ResizeDelta += ColumnResizeHandle_ResizeDelta;
        ProcessColumnResizeHandle.ResizeDelta += ColumnResizeHandle_ResizeDelta;
        CompanyColumnResizeHandle.ResizeDelta += ColumnResizeHandle_ResizeDelta;
        TitleColumnResizeHandle.ResizeDelta += ColumnResizeHandle_ResizeDelta;

        AlertDetailsResizeHandle.ResizeDelta += AlertDetailsResizeHandle_ResizeDelta;
    }

    private void ColumnResizeHandle_ResizeDelta(object? sender, ResizeDeltaEventArgs e)
    {
        if (sender is FrameworkElement element && element.Tag is string column)
        {
            ((AlertTableColumnWidths)Resources["AlertColumnWidths"]).Resize(column, e.HorizontalChange);
        }
    }

    private void AlertDetailsResizeHandle_ResizeDelta(object? sender, ResizeDeltaEventArgs e)
    {
        double nextHeight = AlertDetailsRow.Height.Value - e.VerticalChange;
        nextHeight = Math.Max(140, Math.Min(520, nextHeight));
        AlertDetailsRow.Height = new GridLength(nextHeight);
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
            " loaded rows. Sorted by " + SortLabel(sortColumn) + " " + (sortAscending ? "ascending" : "descending") +
            ". External threshold filter uses MinimumEmailScore=" + externalThreshold + ".";
        AlertsList.SelectedIndex = rows.Count == 0 ? -1 : 0;
        ShowSelectedAlert(rows.Count == 0 ? null : rows[0]);
    }

    private IEnumerable<ArcaneAlertRecord> Sort(IEnumerable<ArcaneAlertRecord> source)
    {
        IOrderedEnumerable<ArcaneAlertRecord> ordered = sortColumn switch
        {
            "Score" => sortAscending ? source.OrderBy(alert => alert.Score) : source.OrderByDescending(alert => alert.Score),
            "Rule" => sortAscending ? source.OrderBy(alert => alert.RuleId) : source.OrderByDescending(alert => alert.RuleId),
            "Category" => sortAscending ? source.OrderBy(alert => alert.Category) : source.OrderByDescending(alert => alert.Category),
            "Country" => sortAscending ? source.OrderBy(alert => alert.Country) : source.OrderByDescending(alert => alert.Country),
            "Process" => sortAscending ? source.OrderBy(alert => alert.Process) : source.OrderByDescending(alert => alert.Process),
            "Company" => sortAscending ? source.OrderBy(alert => alert.Company) : source.OrderByDescending(alert => alert.Company),
            "Title" => sortAscending ? source.OrderBy(alert => alert.Title) : source.OrderByDescending(alert => alert.Title),
            _ => sortAscending ? source.OrderBy(alert => alert.TimestampUtc) : source.OrderByDescending(alert => alert.TimestampUtc)
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

    private void ShowSelectedAlert(ArcaneAlertRecord? alert)
    {
        if (alert == null)
        {
            SelectedAlertHintText.Text = "No selection";
            SelectedAlertMetadataText.Text = "No alerts match the current filters.";
            SelectedAlertEvidenceText.Text = "";
            return;
        }

        SelectedAlertHintText.Text = alert.RuleId + " score " + alert.Score;
        SelectedAlertMetadataText.Text = BuildSelectedAlertMetadataText(alert);
        SelectedAlertEvidenceText.Text = BuildSelectedAlertEvidenceText(alert);
    }

    private void UpdateSortIndicators()
    {
        TimeSortIndicator.Text = "";
        RuleSortIndicator.Text = "";
        CategorySortIndicator.Text = "";
        ScoreSortIndicator.Text = "";
        CountrySortIndicator.Text = "";
        ProcessSortIndicator.Text = "";
        CompanySortIndicator.Text = "";
        TitleSortIndicator.Text = "";

        string indicator = sortAscending ? "\u25B2" : "\u25BC";
        switch (sortColumn)
        {
            case "Rule":
                RuleSortIndicator.Text = indicator;
                break;
            case "Category":
                CategorySortIndicator.Text = indicator;
                break;
            case "Score":
                ScoreSortIndicator.Text = indicator;
                break;
            case "Country":
                CountrySortIndicator.Text = indicator;
                break;
            case "Process":
                ProcessSortIndicator.Text = indicator;
                break;
            case "Company":
                CompanySortIndicator.Text = indicator;
                break;
            case "Title":
                TitleSortIndicator.Text = indicator;
                break;
            default:
                TimeSortIndicator.Text = indicator;
                break;
        }
    }

    private static bool DefaultSortAscending(string column)
    {
        return !column.Equals("Time", StringComparison.OrdinalIgnoreCase) &&
            !column.Equals("Score", StringComparison.OrdinalIgnoreCase);
    }

    private static string SortLabel(string column)
    {
        return column.Equals("Time", StringComparison.OrdinalIgnoreCase) ? "system time" : column.ToLowerInvariant();
    }

    private static string BuildSelectedAlertMetadataText(ArcaneAlertRecord alert)
    {
        return "SystemTime=" + alert.SystemTimeDisplay + Environment.NewLine +
            "UTC=" + alert.TimestampUtc.ToString("u") + Environment.NewLine +
            "Rule=" + alert.RuleId + Environment.NewLine +
            "Category=" + alert.Category + Environment.NewLine +
            "Severity=" + alert.Severity + Environment.NewLine +
            "Score=" + alert.Score + Environment.NewLine +
            "Title=" + alert.Title + Environment.NewLine +
            "Process=" + alert.Process + Environment.NewLine +
            "RemoteIp=" + alert.RemoteIp + Environment.NewLine +
            "Country=" + alert.Country + Environment.NewLine +
            "Company=" + alert.Company + Environment.NewLine +
            "MaintenanceContext=" + alert.MaintenanceContext + Environment.NewLine +
            "ExternalSuppressed=" + alert.ExternalSuppressedByPolicy + Environment.NewLine +
            "ExternalForced=" + alert.ExternalForcedByPolicy + Environment.NewLine +
            "Policy=" + alert.PolicyContext + Environment.NewLine +
            "Recommendation=" + alert.Recommendation;
    }

    private static string BuildSelectedAlertEvidenceText(ArcaneAlertRecord alert)
    {
        return "Entity=" + alert.Entity + Environment.NewLine + Environment.NewLine +
            "Body=" + alert.Body + Environment.NewLine + Environment.NewLine +
            "RawJson=" + alert.RawJson;
    }
}
