using System;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using ArcaneEDR_Gui.Services;

namespace ArcaneEDR_Gui.Pages;

public sealed partial class MaintenancePage : Page
{
    public MaintenancePage()
    {
        InitializeComponent();
        Loaded += async (_, _) => await ListMaintenanceAsync();
    }

    private async void StartMaintenance_Click(object sender, RoutedEventArgs e)
    {
        ArcaneCommandResult result = await ArcaneCommandRunner.RunAsync("--maintenance", "start", "--duration", "30m", "--reason", "gui-maintenance");
        MaintenanceOutputText.Text = result.CombinedText();
    }

    private async void ClearMaintenance_Click(object sender, RoutedEventArgs e)
    {
        ArcaneCommandResult result = await ArcaneCommandRunner.RunAsync("--maintenance", "clear", "--reason", "gui-clear");
        MaintenanceOutputText.Text = result.CombinedText();
    }

    private async void ListMaintenance_Click(object sender, RoutedEventArgs e)
    {
        await ListMaintenanceAsync();
    }

    private async void ValidateAdmin_Click(object sender, RoutedEventArgs e)
    {
        ArcaneCommandResult result = await ArcaneScriptRunner.RunScriptAsync("run-admin-task.cmd", "ValidateAdmin");
        MaintenanceOutputText.Text = result.CombinedText();
    }

    private async void PublishRestart_Click(object sender, RoutedEventArgs e)
    {
        ArcaneCommandResult result = await ArcaneScriptRunner.RunScriptAsync(TimeSpan.FromMinutes(5), "run-admin-task.cmd", "PublishRestart");
        MaintenanceOutputText.Text = result.CombinedText();
    }

    private async void ResponseFirewall_Click(object sender, RoutedEventArgs e)
    {
        ArcaneCommandResult result = await ArcaneCommandRunner.RunAsync("--response-firewall", "list");
        MaintenanceOutputText.Text = result.CombinedText();
    }

    private async void SupportBundle_Click(object sender, RoutedEventArgs e)
    {
        ArcaneCommandResult result = await ArcaneCommandRunner.RunAsync(TimeSpan.FromMinutes(2), "--support-bundle");
        MaintenanceOutputText.Text = result.CombinedText();
    }

    private async System.Threading.Tasks.Task ListMaintenanceAsync()
    {
        ArcaneCommandResult result = await ArcaneCommandRunner.RunAsync("--maintenance", "list", "--last", "24h");
        MaintenanceOutputText.Text = result.CombinedText();
    }
}
