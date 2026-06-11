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

    private async void InstallService_Click(object sender, RoutedEventArgs e)
    {
        ArcaneCommandResult result = await ArcaneScriptRunner.RunScriptAsync(TimeSpan.FromMinutes(5), "run-admin-task.cmd", "InstallService");
        MaintenanceOutputText.Text = result.CombinedText();
    }

    private async void InstallSysmon_Click(object sender, RoutedEventArgs e)
    {
        ArcaneCommandResult result = await ArcaneScriptRunner.RunScriptAsync(TimeSpan.FromMinutes(5), "run-admin-task.cmd", "InstallSysmon");
        MaintenanceOutputText.Text = result.CombinedText();
    }

    private async void PublishRestart_Click(object sender, RoutedEventArgs e)
    {
        ArcaneCommandResult result = await ArcaneScriptRunner.RunScriptAsync(TimeSpan.FromMinutes(5), "run-admin-task.cmd", "PublishRestart");
        MaintenanceOutputText.Text = result.CombinedText();
    }

    private async void UninstallService_Click(object sender, RoutedEventArgs e)
    {
        if (!await ConfirmAsync("Uninstall Arcane EDR service?", "This stops and removes the Windows service. Local config and logs are not deleted.", "Uninstall service"))
        {
            return;
        }

        ArcaneCommandResult result = await ArcaneScriptRunner.RunScriptAsync(TimeSpan.FromMinutes(5), "run-admin-task.cmd", "UninstallService");
        MaintenanceOutputText.Text = result.CombinedText();
    }

    private async void PollOnce_Click(object sender, RoutedEventArgs e)
    {
        ArcaneCommandResult result = await ArcaneCommandRunner.RunAsync(TimeSpan.FromMinutes(2), "--poll-once");
        MaintenanceOutputText.Text = result.CombinedText();
    }

    private async void TestHealth_Click(object sender, RoutedEventArgs e)
    {
        ArcaneCommandResult result = await ArcaneCommandRunner.RunAsync("--test-health");
        MaintenanceOutputText.Text = result.CombinedText();
    }

    private async void TestAlert_Click(object sender, RoutedEventArgs e)
    {
        ArcaneCommandResult result = await ArcaneCommandRunner.RunAsync("--test-alert");
        MaintenanceOutputText.Text = result.CombinedText();
    }

    private async void PreviewAi_Click(object sender, RoutedEventArgs e)
    {
        ArcaneCommandResult result = await ArcaneCommandRunner.RunAsync("--preview-ai-payload");
        MaintenanceOutputText.Text = result.CombinedText();
    }

    private async void TestAi_Click(object sender, RoutedEventArgs e)
    {
        ArcaneCommandResult result = await ArcaneCommandRunner.RunAsync(TimeSpan.FromMinutes(2), "--test-ai-analysis");
        MaintenanceOutputText.Text = result.CombinedText();
    }

    private async void ResponseFirewall_Click(object sender, RoutedEventArgs e)
    {
        ArcaneCommandResult result = await ArcaneCommandRunner.RunAsync("--response-firewall", "list");
        MaintenanceOutputText.Text = result.CombinedText();
    }

    private async void ClearFirewall_Click(object sender, RoutedEventArgs e)
    {
        if (!await ConfirmAsync("Clear Arcane firewall blocks?", "This removes all firewall rules recorded in the Arcane response ledger.", "Clear firewall blocks"))
        {
            return;
        }

        ArcaneCommandResult result = await ArcaneCommandRunner.RunAsync("--response-firewall", "remove-all");
        MaintenanceOutputText.Text = result.CombinedText();
    }

    private async void AgentActivity_Click(object sender, RoutedEventArgs e)
    {
        ArcaneCommandResult result = await ArcaneCommandRunner.RunAsync("--agent-activity", "--last", "24h");
        MaintenanceOutputText.Text = result.CombinedText();
    }

    private async void Incidents_Click(object sender, RoutedEventArgs e)
    {
        ArcaneCommandResult result = await ArcaneCommandRunner.RunAsync("--incidents", "--last", "24h");
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

    private async System.Threading.Tasks.Task<bool> ConfirmAsync(string title, string content, string primaryText)
    {
        ContentDialog dialog = new ContentDialog
        {
            XamlRoot = XamlRoot,
            Title = title,
            Content = content,
            PrimaryButtonText = primaryText,
            CloseButtonText = "Cancel",
            DefaultButton = ContentDialogButton.Close
        };

        ContentDialogResult result = await dialog.ShowAsync();
        return result == ContentDialogResult.Primary;
    }
}
