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
        await PreviewAsync(false);
    }

    private async void Json_Click(object sender, RoutedEventArgs e)
    {
        await PreviewAsync(true);
    }

    private async void Send_Click(object sender, RoutedEventArgs e)
    {
        ArcaneCommandResult result = await ArcaneCommandRunner.RunAsync(TimeSpan.FromMinutes(2), "--test-daily-report");
        ReportOutputText.Text = result.CombinedText();
    }

    private async System.Threading.Tasks.Task PreviewAsync(bool json)
    {
        ArcaneCommandResult result = json
            ? await ArcaneCommandRunner.RunAsync("--preview-daily-report", "--json")
            : await ArcaneCommandRunner.RunAsync("--preview-daily-report");
        ReportOutputText.Text = result.CombinedText();
    }
}
