using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using ArcaneEDR_Gui.Services;

namespace ArcaneEDR_Gui.Pages;

public sealed partial class PolicyPage : Page
{
    public PolicyPage()
    {
        InitializeComponent();
        Loaded += async (_, _) => await InspectAsync();
    }

    private async void Inspect_Click(object sender, RoutedEventArgs e)
    {
        await InspectAsync();
    }

    private async void Preview_Click(object sender, RoutedEventArgs e)
    {
        ArcaneCommandResult result = await ArcaneCommandRunner.RunAsync(
            "--policy-preview",
            "--sample-rule",
            "NET-BEACON-TIMING-LOW-RISK",
            "--sample-process",
            "codex.exe",
            "--sample-score",
            "55");
        PolicyOutputText.Text = result.CombinedText();
    }

    private void OpenPolicy_Click(object sender, RoutedEventArgs e)
    {
        ArcaneScriptRunner.OpenPath(ArcanePaths.Discover().PolicyFile);
    }

    private async void Help_Click(object sender, RoutedEventArgs e)
    {
        await GuiHelp.ShowAsync(
            XamlRoot,
            "Policy help",
            "Policy rules are the safest place for narrow local tuning because they can lower, suppress externally, raise, force, or tag specific patterns without deleting local alert evidence.\n\n" +
            "Inspect validates the policy file shape. Preview tests a sample match so you can check deterministic behavior before relying on a rule.\n\n" +
            "Use suppress_external for repeated benign notifications when you still want local logs, daily report context, and support bundle evidence.");
    }

    private async System.Threading.Tasks.Task InspectAsync()
    {
        ArcaneCommandResult result = await ArcaneCommandRunner.RunAsync("--policy-inspect");
        PolicyOutputText.Text = result.CombinedText();
    }
}
