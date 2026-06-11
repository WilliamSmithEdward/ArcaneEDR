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

    private async void Help_Click(object sender, RoutedEventArgs e)
    {
        await GuiHelp.ShowAsync(
            XamlRoot,
            "Maintenance help",
            "Maintenance markers tell Arcane that expected operator work is underway. They should reduce noisy interpretation without deleting local evidence.\n\n" +
            "Admin tasks can change Windows service state, install Sysmon telemetry, publish binaries, restart Arcane, or remove service/firewall state. Those actions require confirmation when they can affect the workstation.\n\n" +
            "Preview commands are safest. Test commands may send live provider calls or notifications depending on config.");
    }

    private async void ValidateAdmin_Click(object sender, RoutedEventArgs e)
    {
        ArcaneCommandResult result = await ArcaneScriptRunner.RunScriptAsync("run-admin-task.cmd", "ValidateAdmin");
        MaintenanceOutputText.Text = result.CombinedText();
    }

    private async void InstallService_Click(object sender, RoutedEventArgs e)
    {
        if (!await GuiHelp.ConfirmRiskAsync(
            XamlRoot,
            "Install or repair Arcane EDR service?",
            "This runs the elevated service install task. It may register, replace, or start the ArcaneEDR Windows service.\n\n" +
            "Expected effect: Arcane runs continuously in the background using the installed config and writes local logs/evidence.\n\n" +
            "Rollback path: use Uninstall Service or Windows Services if you need to remove or stop it.",
            "Install service"))
        {
            MaintenanceOutputText.Text = "Install service canceled.";
            return;
        }

        ArcaneCommandResult result = await ArcaneScriptRunner.RunScriptAsync(TimeSpan.FromMinutes(5), "run-admin-task.cmd", "InstallService");
        MaintenanceOutputText.Text = result.CombinedText();
    }

    private async void InstallSysmon_Click(object sender, RoutedEventArgs e)
    {
        if (!await GuiHelp.ConfirmRiskAsync(
            XamlRoot,
            "Install or configure Sysmon?",
            "This runs the elevated Sysmon install task. Sysmon adds Windows telemetry that Arcane reads for process, network, file, and related security events.\n\n" +
            "Expected effect: more complete detection coverage, with additional event volume in the Windows event logs.\n\n" +
            "Rollback path: use the documented Sysmon uninstall path or restore the previous Sysmon configuration.",
            "Install Sysmon"))
        {
            MaintenanceOutputText.Text = "Install Sysmon canceled.";
            return;
        }

        ArcaneCommandResult result = await ArcaneScriptRunner.RunScriptAsync(TimeSpan.FromMinutes(5), "run-admin-task.cmd", "InstallSysmon");
        MaintenanceOutputText.Text = result.CombinedText();
    }

    private async void PublishRestart_Click(object sender, RoutedEventArgs e)
    {
        if (!await GuiHelp.ConfirmRiskAsync(
            XamlRoot,
            "Publish and restart Arcane EDR?",
            "This runs the elevated publish/restart task. It can replace installed Arcane binaries and restart the Windows service.\n\n" +
            "Expected effect: brief telemetry gap during restart, followed by a service-start notification when notification delivery is enabled.\n\n" +
            "Rollback path: reinstall the previous release or stop the service if the new build is not healthy.",
            "Publish restart"))
        {
            MaintenanceOutputText.Text = "Publish restart canceled.";
            return;
        }

        ArcaneCommandResult result = await ArcaneScriptRunner.RunScriptAsync(TimeSpan.FromMinutes(5), "run-admin-task.cmd", "PublishRestart");
        MaintenanceOutputText.Text = result.CombinedText();
    }

    private async void UninstallService_Click(object sender, RoutedEventArgs e)
    {
        if (!await GuiHelp.ConfirmRiskAsync(
            XamlRoot,
            "Uninstall Arcane EDR service?",
            "This stops and removes the Windows service. Local config, policy, and logs are not deleted.\n\n" +
            "Expected effect: Arcane no longer polls continuously until you reinstall or run it manually.",
            "Uninstall service"))
        {
            MaintenanceOutputText.Text = "Uninstall service canceled.";
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
        if (!await GuiHelp.ConfirmRiskAsync(
            XamlRoot,
            "Send a test alert?",
            "This requests a test alert through the configured alerting path. Depending on config, it may send a real email, webhook, local JSONL notification, or Windows Event Log record.",
            "Send test alert"))
        {
            MaintenanceOutputText.Text = "Test alert canceled.";
            return;
        }

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
        if (!await GuiHelp.ConfirmRiskAsync(
            XamlRoot,
            "Call the AI analysis provider?",
            "This sends a compact redacted test payload to the configured AI provider when AI analysis is enabled and credentials are available.\n\n" +
            "Preview AI Payload first if you want to inspect the payload shape without making an external API call.",
            "Test AI"))
        {
            MaintenanceOutputText.Text = "Test AI canceled.";
            return;
        }

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
        if (!await GuiHelp.ConfirmRiskAsync(
            XamlRoot,
            "Clear Arcane firewall blocks?",
            "This removes all firewall rules recorded in the Arcane response ledger.\n\n" +
            "Expected effect: previously blocked remote IPs may become reachable again if no other firewall rule blocks them.",
            "Clear firewall blocks"))
        {
            MaintenanceOutputText.Text = "Clear firewall canceled.";
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

}
