using Microsoft.UI.Xaml.Controls;
using ArcaneEDR_Gui.Services;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

// To learn more about WinUI, the WinUI project structure,
// and more about our project templates, see: http://aka.ms/winui-project-info.

namespace ArcaneEDR_Gui.Pages;

public sealed partial class HomePage : Page
{
    private CancellationTokenSource? refreshCancellation;
    private int refreshGeneration;
    private bool pageLoaded;

    public HomePage()
    {
        InitializeComponent();
        Loaded += HomePage_Loaded;
        Unloaded += HomePage_Unloaded;
    }

    private async void Refresh_Click(object sender, Microsoft.UI.Xaml.RoutedEventArgs e)
    {
        await RefreshSafeAsync();
    }

    private async void HomePage_Loaded(object sender, Microsoft.UI.Xaml.RoutedEventArgs e)
    {
        pageLoaded = true;
        await RefreshSafeAsync();
    }

    private void HomePage_Unloaded(object sender, Microsoft.UI.Xaml.RoutedEventArgs e)
    {
        pageLoaded = false;
        refreshCancellation?.Cancel();
    }

    private async void Help_Click(object sender, Microsoft.UI.Xaml.RoutedEventArgs e)
    {
        await GuiHelp.ShowAsync(
            XamlRoot,
            "Overview help",
            "Overview answers two questions: is Arcane healthy, and what should I review next?\n\n" +
            "The top summary stays plain-language. Review queue shows the most actionable local evidence from the last 24 hours. Configuration validation separates real blockers from standard-user warnings.\n\n" +
            "Use Refresh after service restarts, MSI installs, or local config edits.");
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
            // Navigation away from Overview cancels in-flight refresh work.
        }
        catch (Exception ex)
        {
            GuiDiagnostics.LogException("overview-refresh", ex);
            if (IsCurrentRefresh(generation, token))
            {
                StatusHeadingText.Text = "Overview could not refresh";
                StatusDetailText.Text = ex.Message;
                NextActionText.Text = "Open Configuration > Validate or try Refresh again.";
            }
        }
    }

    private async Task RefreshAsync(int generation, CancellationToken token)
    {
        ArcaneHealthSnapshot health = await ArcaneStateReader.ReadHealthAsync();
        token.ThrowIfCancellationRequested();
        if (!IsCurrentRefresh(generation, token)) return;

        ServiceStateText.Text = health.ServiceState;
        PollCountText.Text = health.PollCount;
        AlertCountText.Text = health.AlertCount;
        FailureCountText.Text = health.PollFailures + " / " + health.ExternalSendFailures;
        HealthText.Text = BuildHealthSummary(health);

        ArcaneValidationReport validation = await ArcaneValidationView.RunAsync();
        token.ThrowIfCancellationRequested();
        if (!IsCurrentRefresh(generation, token)) return;

        ValidationHeadingText.Text = ArcaneValidationView.Heading(validation);
        OutputText.Text = ArcaneValidationView.BuildOverviewText(validation);

        List<ArcaneAlertRecord> alerts = ArcaneAlertStore.ReadAlerts();
        List<ArcaneOverviewRecommendation> recommendations = ArcaneAlertStore.BuildRecommendations(alerts, health, validation).ToList();
        if (!IsCurrentRefresh(generation, token)) return;

        RecommendationsList.ItemsSource = recommendations;
        SignalSummaryText.Text = BuildSignalSummary(alerts);
        StatusHeadingText.Text = BuildStatusHeading(health, validation, alerts);
        StatusDetailText.Text = BuildStatusDetail(health, validation, alerts);
        NextActionText.Text = BuildNextAction(recommendations);
    }

    private bool IsCurrentRefresh(int generation, CancellationToken token)
    {
        return pageLoaded &&
            XamlRoot != null &&
            !token.IsCancellationRequested &&
            generation == Volatile.Read(ref refreshGeneration);
    }

    private static string BuildSignalSummary(IReadOnlyList<ArcaneAlertRecord> alerts)
    {
        DateTime cutoff = DateTime.UtcNow.AddHours(-24);
        List<ArcaneAlertRecord> recent = alerts.Where(alert => alert.TimestampUtc >= cutoff).ToList();
        int critical = recent.Count(alert => alert.Score >= 90 || alert.Severity.Equals("critical", StringComparison.OrdinalIgnoreCase));
        int high = recent.Count(alert => alert.Score >= 75 && alert.Score < 90);
        int suppressed = recent.Count(alert => alert.ExternalSuppressedByPolicy || alert.PolicyContext.IndexOf("suppress", StringComparison.OrdinalIgnoreCase) >= 0);
        string topRule = recent
            .GroupBy(alert => alert.RuleId)
            .OrderByDescending(group => group.Count())
            .Select(group => group.Key + " (" + group.Count() + ")")
            .FirstOrDefault() ?? "none";

        if (recent.Count == 0)
        {
            return "No local alerts in the last 24 hours.";
        }

        return recent.Count + " local alerts in the last 24 hours." + Environment.NewLine +
            critical + " critical, " + high + " high." + Environment.NewLine +
            suppressed + " were kept locally while external delivery was suppressed." + Environment.NewLine +
            "Most frequent rule: " + topRule + ".";
    }

    private static string BuildStatusHeading(ArcaneHealthSnapshot health, ArcaneValidationReport validation, IReadOnlyList<ArcaneAlertRecord> alerts)
    {
        if (!health.ServiceState.Equals("Running", StringComparison.OrdinalIgnoreCase))
        {
            return "Arcane service needs attention";
        }

        if (validation.ErrorCount > 0)
        {
            return "Configuration needs attention";
        }

        DateTime cutoff = DateTime.UtcNow.AddHours(-24);
        bool hasCritical = alerts.Any(alert => alert.TimestampUtc >= cutoff &&
            (alert.Score >= 90 || alert.Severity.Equals("critical", StringComparison.OrdinalIgnoreCase)));
        if (hasCritical)
        {
            return "Critical alert needs review";
        }

        if (validation.WarningCount > 0)
        {
            return "Arcane is running with validation warnings";
        }

        return "Arcane is running";
    }

    private static string BuildStatusDetail(ArcaneHealthSnapshot health, ArcaneValidationReport validation, IReadOnlyList<ArcaneAlertRecord> alerts)
    {
        DateTime cutoff = DateTime.UtcNow.AddHours(-24);
        int recent = alerts.Count(alert => alert.TimestampUtc >= cutoff);
        int critical = alerts.Count(alert => alert.TimestampUtc >= cutoff &&
            (alert.Score >= 90 || alert.Severity.Equals("critical", StringComparison.OrdinalIgnoreCase)));
        int high = alerts.Count(alert => alert.TimestampUtc >= cutoff && alert.Score >= 75 && alert.Score < 90);

        List<string> parts = new List<string>();
        parts.Add("Service: " + health.ServiceState + ".");
        parts.Add("Validation: " + validation.ErrorCount + " blocker(s), " + validation.WarningCount + " warning(s).");
        parts.Add("Last 24 hours: " + recent + " alert(s), including " + critical + " critical and " + high + " high.");
        return String.Join(" ", parts);
    }

    private static string BuildNextAction(IReadOnlyList<ArcaneOverviewRecommendation> recommendations)
    {
        ArcaneOverviewRecommendation? first = recommendations.FirstOrDefault();
        if (first == null)
        {
            return "No immediate action. Open Alerts only if you are tuning baseline noise.";
        }

        if (first.Priority.Equals("Clear", StringComparison.OrdinalIgnoreCase))
        {
            return "No immediate action. Keep Arcane running and review lower-score baseline activity when convenient.";
        }

        return first.Title + ": " + first.Detail;
    }

    private static string BuildHealthSummary(ArcaneHealthSnapshot health)
    {
        return "Started: " + FormatLocalTime(health.LastStartUtc) + Environment.NewLine +
            "Last heartbeat: " + FormatLocalTime(health.LastHeartbeatUtc) + Environment.NewLine +
            "Last daily report: " + FormatLocalTime(health.LastDailySummaryUtc) + Environment.NewLine +
            "Last AI review: " + FormatLocalTime(health.LastAIAnalysisUtc);
    }

    private static string FormatLocalTime(string utcText)
    {
        if (String.IsNullOrWhiteSpace(utcText)) return "not recorded";
        if (DateTime.TryParse(utcText, out DateTime parsed))
        {
            DateTime utc = parsed.Kind == DateTimeKind.Utc ? parsed : DateTime.SpecifyKind(parsed, DateTimeKind.Utc);
            return TimeZoneInfo.ConvertTimeFromUtc(utc, TimeZoneInfo.Local).ToString("yyyy-MM-dd HH:mm:ss");
        }

        return utcText;
    }
}
