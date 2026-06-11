using Microsoft.UI.Xaml.Controls;
using ArcaneEDR_Gui.Services;

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
            "LastAIAnalysisUtc=" + health.LastAIAnalysisUtc + System.Environment.NewLine +
            "HealthFile=" + health.HealthFile;
        PathText.Text = ArcaneStateReader.BuildPathSummary();

        ArcaneCommandResult result = await ArcaneCommandRunner.RunAsync("--validate-config");
        OutputText.Text = result.CombinedText();
    }
}
