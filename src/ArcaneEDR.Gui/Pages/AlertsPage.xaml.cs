using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Input;
using Windows.ApplicationModel.DataTransfer;
using ArcaneEDR_Gui.Controls;
using ArcaneEDR_Gui.Services;

namespace ArcaneEDR_Gui.Pages;

public sealed partial class AlertsPage : Page
{
    private List<ArcaneAlertRecord> allAlerts = new List<ArcaneAlertRecord>();
    private double externalThreshold = 60;
    private bool loaded;
    private bool restoringView;
    private string restoredCategory = "Any";
    private string sortColumn = "Time";
    private bool sortAscending;
    private List<ArcaneAlertRecord> visibleAlerts = new List<ArcaneAlertRecord>();
    private CancellationTokenSource? refreshCancellation;
    private int refreshGeneration;
    private ArcaneAlertRecord? contextMenuAlert;
    private const double MinAlertDetailsHeight = 140;
    private const double MaxAlertDetailsHeight = 360;

    public AlertsPage()
    {
        InitializeComponent();
        RestoreViewSettings();
        ConfigureResizeHandles();
        UpdateSortIndicators();
        Loaded += AlertsPage_Loaded;
        Unloaded += AlertsPage_Unloaded;
    }

    private async void Refresh_Click(object sender, RoutedEventArgs e)
    {
        await RefreshSafeAsync();
    }

    private async void AlertsPage_Loaded(object sender, RoutedEventArgs e)
    {
        loaded = true;
        await RefreshSafeAsync();
    }

    private void AlertsPage_Unloaded(object sender, RoutedEventArgs e)
    {
        loaded = false;
        refreshCancellation?.Cancel();
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
            "The bell column shows whether Arcane recorded an external notification outcome for a row. Hover it to see sent, grouped, suppressed, rate-limited, provider unavailable, or not-recorded details.\n\n" +
            "Country and company values come from enrichment. Missing company data is not proof of compromise; pair it with process, rule, score, country, and policy context.\n\n" +
            "Right-click an alert row, or use Create policy in the metadata panel, to start a guided policy draft from alert metadata.\n\n" +
            "Copy CSV and Export use the current filtered/sorted table view only. Raw JSONL remains available for exact evidence when you need the underlying record.");
    }

    private void CopyCsv_Click(object sender, RoutedEventArgs e)
    {
        DataPackage package = new DataPackage();
        package.SetText(BuildCsv(visibleAlerts));
        Clipboard.SetContent(package);
        TableSummaryText.Text = "Copied " + visibleAlerts.Count.ToString(CultureInfo.InvariantCulture) + " visible alert row(s) as CSV.";
    }

    private void ExportCsv_Click(object sender, RoutedEventArgs e)
    {
        string directory = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "Arcane EDR",
            "exports");
        Directory.CreateDirectory(directory);
        string path = Path.Combine(directory, "ArcaneAlerts-" + DateTime.Now.ToString("yyyyMMdd-HHmmss", CultureInfo.InvariantCulture) + ".csv");
        File.WriteAllText(path, BuildCsv(visibleAlerts), Encoding.UTF8);
        TableSummaryText.Text = "Exported " + visibleAlerts.Count.ToString(CultureInfo.InvariantCulture) + " visible alert row(s) to " + path;
        ArcaneScriptRunner.OpenPath(directory);
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

    private void AlertRow_RightTapped(object sender, RightTappedRoutedEventArgs e)
    {
        if (sender is FrameworkElement element && element.DataContext is ArcaneAlertRecord alert)
        {
            contextMenuAlert = alert;
            AlertsList.SelectedItem = alert;
        }
    }

    private async void CreatePolicyFromAlert_Click(object sender, RoutedEventArgs e)
    {
        ArcaneAlertRecord? alert = (sender as MenuFlyoutItem)?.CommandParameter as ArcaneAlertRecord ??
            (sender as FrameworkElement)?.DataContext as ArcaneAlertRecord ??
            contextMenuAlert ??
            AlertsList.SelectedItem as ArcaneAlertRecord;
        if (alert == null)
        {
            TableSummaryText.Text = "Select an alert row before creating a policy.";
            return;
        }

        AlertsList.SelectedItem = alert;

        PolicyWizardResult result = await PolicyWizard.ShowAsync(XamlRoot, alert);
        if (result.Saved)
        {
            TableSummaryText.Text = "Saved policy " + result.Id + ". " + result.Status;
        }
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
        NotificationColumnResizeHandle.ResizeDelta += ColumnResizeHandle_ResizeDelta;
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
        nextHeight = Math.Max(MinAlertDetailsHeight, Math.Min(MaxAlertDetailsHeight, nextHeight));
        AlertDetailsRow.Height = new GridLength(nextHeight);
        SaveViewSettings();
    }

    private async Task RefreshSafeAsync()
    {
        int generation = Interlocked.Increment(ref refreshGeneration);
        refreshCancellation?.Cancel();
        refreshCancellation?.Dispose();
        refreshCancellation = new CancellationTokenSource();
        CancellationToken token = refreshCancellation.Token;

        try
        {
            await RefreshAsync(generation, token);
        }
        catch (OperationCanceledException)
        {
            // Navigation away from Alerts cancels in-flight refresh work.
        }
        catch (Exception ex)
        {
            GuiDiagnostics.LogException("alerts-refresh", ex);
            if (IsCurrentRefresh(generation, token))
            {
                TableSummaryText.Text = "Alerts could not refresh: " + ex.Message;
            }
        }
    }

    private async Task RefreshAsync(int generation, CancellationToken token)
    {
        ArcaneConfigBundle config = ArcaneConfigBundle.Load();
        externalThreshold = config.Runtime.GetNumber("MinimumEmailScore", 60);
        if (!IsCurrentRefresh(generation, token)) return;

        AlertConfigContextText.Text =
            "ExternalAlertProvider=" + config.Runtime.Get("ExternalAlertProvider", "Disabled") + Environment.NewLine +
            "MinimumEmailScore=" + externalThreshold + Environment.NewLine +
            "BaselineLearningMode=" + config.Runtime.Get("BaselineLearningMode", "false") + Environment.NewLine +
            "EnableExternalAlertGrouping=" + config.Runtime.Get("EnableExternalAlertGrouping", "false") + Environment.NewLine +
            "RuleMinimumEmailScores=" + config.Runtime.Get("RuleMinimumEmailScores", "");

        string lookback = SelectedLookback();
        ArcaneCommandResult result = await ArcaneCommandRunner.RunAsync("--alert-volume", "--last", lookback.Equals("All", StringComparison.OrdinalIgnoreCase) ? "7d" : lookback);
        token.ThrowIfCancellationRequested();
        if (!IsCurrentRefresh(generation, token)) return;

        VolumeText.Text = result.CombinedText();
        RecentAlertsText.Text = ArcaneStateReader.ReadRecentAlerts(80);

        allAlerts = ArcaneAlertStore.ReadAlerts(5000);
        if (!IsCurrentRefresh(generation, token)) return;

        PopulateCategories();
        ApplyFilters();
    }

    private bool IsCurrentRefresh(int generation, CancellationToken token)
    {
        return loaded &&
            XamlRoot != null &&
            !token.IsCancellationRequested &&
            generation == Volatile.Read(ref refreshGeneration);
    }

    private void PopulateCategories()
    {
        string selected = ComboText(CategoryBox, "Any");
        if (!String.IsNullOrWhiteSpace(restoredCategory))
        {
            selected = restoredCategory;
        }

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
                restoredCategory = "";
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
        visibleAlerts = rows;
        AlertsList.ItemsSource = rows;
        TableSummaryText.Text = rows.Count + " visible of " + allAlerts.Count +
            " loaded rows. Sorted by " + SortLabel(sortColumn) + " " + (sortAscending ? "ascending" : "descending") +
            ". External threshold filter uses MinimumEmailScore=" + externalThreshold + ".";
        AlertsList.SelectedIndex = rows.Count == 0 ? -1 : 0;
        ShowSelectedAlert(rows.Count == 0 ? null : rows[0]);
        SaveViewSettings();
    }

    private IEnumerable<ArcaneAlertRecord> Sort(IEnumerable<ArcaneAlertRecord> source)
    {
        IOrderedEnumerable<ArcaneAlertRecord> ordered = sortColumn switch
        {
            "Score" => sortAscending ? source.OrderBy(alert => alert.Score) : source.OrderByDescending(alert => alert.Score),
            "Rule" => sortAscending ? source.OrderBy(alert => alert.RuleId) : source.OrderByDescending(alert => alert.RuleId),
            "Category" => sortAscending ? source.OrderBy(alert => alert.Category) : source.OrderByDescending(alert => alert.Category),
            "Notification" => sortAscending ? source.OrderBy(alert => alert.ExternalNotificationStatusLabel) : source.OrderByDescending(alert => alert.ExternalNotificationStatusLabel),
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
            Contains(alert.ExternalNotificationStatusLabel, search) ||
            Contains(alert.ExternalNotificationReason, search) ||
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
            CreatePolicyFromSelectedAlertButton.IsEnabled = false;
            SelectedAlertHintText.Text = "No selection";
            SelectedAlertMetadataText.Text = "No alerts match the current filters.";
            SelectedAlertEvidenceText.Text = "";
            return;
        }

        CreatePolicyFromSelectedAlertButton.IsEnabled = true;
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
        NotificationSortIndicator.Text = "";
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
            case "Notification":
                NotificationSortIndicator.Text = indicator;
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
            "Notification=" + alert.ExternalNotificationStatusLabel + Environment.NewLine +
            "NotificationStatus=" + alert.ExternalNotificationStatus + Environment.NewLine +
            "NotificationSent=" + alert.ExternalNotificationSent + Environment.NewLine +
            "NotificationProvider=" + alert.ExternalNotificationProvider + Environment.NewLine +
            "NotificationReason=" + alert.ExternalNotificationReason + Environment.NewLine +
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

    private void RestoreViewSettings()
    {
        restoringView = true;
        GuiUserSettings settings = GuiStartupSettings.Load();
        SetCombo(LookbackBox, settings.AlertLookback, "24h");
        SetCombo(SeverityBox, settings.AlertSeverity, "Any");
        restoredCategory = String.IsNullOrWhiteSpace(settings.AlertCategory) ? "Any" : settings.AlertCategory;
        SearchBox.Text = settings.AlertSearch ?? "";
        ExternalCandidatesBox.IsChecked = settings.AlertExternalThresholdOnly;
        sortColumn = String.IsNullOrWhiteSpace(settings.AlertSortColumn) ? "Time" : settings.AlertSortColumn;
        sortAscending = settings.AlertSortAscending;
        double height = Math.Max(MinAlertDetailsHeight, Math.Min(MaxAlertDetailsHeight, settings.AlertDetailsHeight));
        if (height >= MinAlertDetailsHeight && height <= MaxAlertDetailsHeight)
        {
            AlertDetailsRow.Height = new GridLength(height);
        }

        restoringView = false;
    }

    private void SaveViewSettings()
    {
        if (!loaded || restoringView) return;

        GuiUserSettings settings = GuiStartupSettings.Load();
        settings.AlertLookback = SelectedLookback();
        settings.AlertSeverity = ComboText(SeverityBox, "Any");
        settings.AlertCategory = ComboText(CategoryBox, "Any");
        settings.AlertSearch = SearchBox.Text.Trim();
        settings.AlertExternalThresholdOnly = ExternalCandidatesBox.IsChecked == true;
        settings.AlertSortColumn = sortColumn;
        settings.AlertSortAscending = sortAscending;
        settings.AlertDetailsHeight = AlertDetailsRow.Height.Value;
        GuiStartupSettings.SaveAndApply(settings);
    }

    private static void SetCombo(ComboBox comboBox, string value, string fallback)
    {
        string desired = String.IsNullOrWhiteSpace(value) ? fallback : value;
        for (int index = 0; index < comboBox.Items.Count; index++)
        {
            if (comboBox.Items[index] is ComboBoxItem item &&
                desired.Equals(item.Content?.ToString(), StringComparison.OrdinalIgnoreCase))
            {
                comboBox.SelectedIndex = index;
                return;
            }
        }

        comboBox.SelectedIndex = 0;
    }

    private static string BuildCsv(IReadOnlyList<ArcaneAlertRecord> rows)
    {
        StringBuilder builder = new StringBuilder();
        builder.AppendLine("SystemTime,UTC,Rule,Category,Severity,Score,Notification,NotificationStatus,NotificationSent,NotificationProvider,Process,RemoteIp,Country,Company,Title,MaintenanceContext,ExternalSuppressed,ExternalForced,PolicyContext");
        foreach (ArcaneAlertRecord row in rows)
        {
            builder.AppendLine(String.Join(",", new[]
            {
                Csv(row.SystemTimeDisplay),
                Csv(row.TimestampUtc.ToString("u", CultureInfo.InvariantCulture)),
                Csv(row.RuleId),
                Csv(row.Category),
                Csv(row.Severity),
                Csv(row.Score.ToString(CultureInfo.InvariantCulture)),
                Csv(row.ExternalNotificationStatusLabel),
                Csv(row.ExternalNotificationStatus),
                Csv(row.ExternalNotificationSent.ToString()),
                Csv(row.ExternalNotificationProvider),
                Csv(row.Process),
                Csv(row.RemoteIp),
                Csv(row.Country),
                Csv(row.Company),
                Csv(row.Title),
                Csv(row.MaintenanceContext.ToString()),
                Csv(row.ExternalSuppressedByPolicy.ToString()),
                Csv(row.ExternalForcedByPolicy.ToString()),
                Csv(row.PolicyContext)
            }));
        }

        return builder.ToString();
    }

    private static string Csv(string value)
    {
        string safe = value ?? "";
        return "\"" + safe.Replace("\"", "\"\"") + "\"";
    }
}
