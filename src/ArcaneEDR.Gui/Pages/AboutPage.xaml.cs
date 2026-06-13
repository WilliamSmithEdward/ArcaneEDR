using Microsoft.UI.Xaml.Controls;
using ArcaneEDR_Gui.Services;

namespace ArcaneEDR_Gui.Pages;

public sealed partial class AboutPage : Page
{
    public AboutPage()
    {
        InitializeComponent();
        ContextText.Text = ArcaneStateReader.BuildPathSummary();
        Loaded += async (_, _) => await LoadVersionAsync();
    }

    private async void Version_Click(object sender, Microsoft.UI.Xaml.RoutedEventArgs e)
    {
        await LoadVersionAsync();
    }

    private async System.Threading.Tasks.Task LoadVersionAsync()
    {
        ArcaneCommandResult result = await ArcaneCommandRunner.RunAsync("--version");
        AboutOutputText.Text = result.CombinedText();
    }
}
