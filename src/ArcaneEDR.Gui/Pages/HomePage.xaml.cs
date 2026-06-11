using Microsoft.UI.Xaml.Controls;
using ArcaneEDR_Gui.Services;
using System;
using System.Collections.Generic;
using System.Linq;

// To learn more about WinUI, the WinUI project structure,
// and more about our project templates, see: http://aka.ms/winui-project-info.

namespace ArcaneEDR_Gui.Pages;

public sealed partial class HomePage : Page
{
    public HomePage()
    {
        InitializeComponent();
        Loaded += async (_, _) => await RefreshAsync();
    }

    private async void Refresh_Click(object sender, Microsoft.UI.Xaml.RoutedEventArgs e)
    {
        await RefreshAsync();
    }

    private async System.Threading.Tasks.Task RefreshAsync()
    {
        ArcaneHealthSnapshot health = ArcaneStateReader.ReadHealth();
        ServiceStateText.Text = health.ServiceState;
        PollCountText.Text = health.PollCount;
        AlertCountText.Text = health.AlertCount;
        FailureCountText.Text = health.PollFailures + " / " + health.ExternalSendFailures;
        HealthText.Text =
            "LastStartUtc=" + health.LastStartUtc + System.Environment.NewLine +
            "LastHeartbeatUtc=" + health.LastHeartbeatUtc + System.Environment.NewLine +
            "LastDailySummaryUtc=" + health.LastDailySummaryUtc + System.Environment.NewLine +
            "LastAIAnalysisUtc=" + health.LastAIAnalysisUtc;

        ArcaneCommandResult result = await ArcaneCommandRunner.RunAsync("--validate-config");
        string validationText = result.CombinedText();
        OutputText.Text = ExtractValidationBlockers(validationText);

        List<ArcaneAlertRecord> alerts = ArcaneAlertStore.ReadAlerts();
        RecommendationsList.ItemsSource = ArcaneAlertStore.BuildRecommendations(alerts, health, validationText);
        SignalSummaryText.Text = BuildSignalSummary(alerts);
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

        return "Last 24h alerts=" + recent.Count + Environment.NewLine +
            "Critical=" + critical + Environment.NewLine +
            "High=" + high + Environment.NewLine +
            "Externally suppressed/local evidence=" + suppressed + Environment.NewLine +
            "Most frequent rule=" + topRule;
    }

    private static string ExtractValidationBlockers(string validationText)
    {
        List<string> lines = validationText
            .Split(new[] { "\r\n", "\n" }, StringSplitOptions.None)
            .Where(line =>
                line.IndexOf("[FAIL]", StringComparison.OrdinalIgnoreCase) >= 0 ||
                line.IndexOf("[WARN]", StringComparison.OrdinalIgnoreCase) >= 0 ||
                line.IndexOf("summary", StringComparison.OrdinalIgnoreCase) >= 0)
            .ToList();

        return lines.Count == 0 ? "No validation blockers reported." : String.Join(Environment.NewLine, lines);
    }
}
