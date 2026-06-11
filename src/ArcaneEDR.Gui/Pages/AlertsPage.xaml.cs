using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using ArcaneEDR_Gui.Services;

namespace ArcaneEDR_Gui.Pages;

public sealed partial class AlertsPage : Page
{
    public AlertsPage()
    {
        InitializeComponent();
        Loaded += async (_, _) => await RefreshAsync();
    }

    private async void Refresh_Click(object sender, RoutedEventArgs e)
    {
        await RefreshAsync();
    }

    private void OpenLogs_Click(object sender, RoutedEventArgs e)
    {
        ArcaneScriptRunner.OpenPath(ArcanePaths.Discover().LogDirectory);
    }

    private async System.Threading.Tasks.Task RefreshAsync()
    {
        string lookback = SelectedLookback();
        ArcaneCommandResult result = await ArcaneCommandRunner.RunAsync("--alert-volume", "--last", lookback);
        VolumeText.Text = result.CombinedText();
        RecentAlertsText.Text = ArcaneStateReader.ReadRecentAlerts(12);
    }

    private string SelectedLookback()
    {
        ComboBoxItem? item = LookbackBox.SelectedItem as ComboBoxItem;
        return item == null ? "24h" : item.Content.ToString() ?? "24h";
    }
}
