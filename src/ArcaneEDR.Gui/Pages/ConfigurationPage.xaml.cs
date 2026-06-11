using System.IO;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using ArcaneEDR_Gui.Services;

namespace ArcaneEDR_Gui.Pages;

public sealed partial class ConfigurationPage : Page
{
    public ConfigurationPage()
    {
        InitializeComponent();
        Loaded += async (_, _) => await RefreshAsync();
    }

    private async void Validate_Click(object sender, RoutedEventArgs e)
    {
        await RefreshAsync();
    }

    private void OpenConfig_Click(object sender, RoutedEventArgs e)
    {
        ArcaneScriptRunner.OpenPath(ArcanePaths.Discover().ConfigFile);
    }

    private void OpenFolder_Click(object sender, RoutedEventArgs e)
    {
        string config = ArcanePaths.Discover().ConfigFile;
        ArcaneScriptRunner.OpenPath(Path.GetDirectoryName(config) ?? config);
    }

    private async void ResetConfig_Click(object sender, RoutedEventArgs e)
    {
        if (ResetConfirmBox.IsChecked != true)
        {
            ValidationText.Text = "Check the reset confirmation box before replacing local config.";
            return;
        }

        string resetResult = ArcaneConfigMaintenance.ResetLocalConfigToDefaults();
        ResetConfirmBox.IsChecked = false;
        await RefreshAsync();
        ValidationText.Text = resetResult + System.Environment.NewLine + System.Environment.NewLine + ValidationText.Text;
    }

    private async System.Threading.Tasks.Task RefreshAsync()
    {
        PathText.Text = ArcaneStateReader.BuildPathSummary();
        ArcaneCommandResult result = await ArcaneCommandRunner.RunAsync("--validate-config");
        ValidationText.Text = result.CombinedText();
    }
}
