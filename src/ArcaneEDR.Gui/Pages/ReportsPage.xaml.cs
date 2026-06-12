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
            return result.CombinedText();
        });
    }
}
