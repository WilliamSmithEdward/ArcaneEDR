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
        await RunMaintenanceAsync(sender, "Starting maintenance marker...", async () =>
            await ArcaneCommandRunner.RunAsync("--maintenance", "start", "--duration", "30m", "--reason", "gui-maintenance"));
    }

    private async void ClearMaintenance_Click(object sender, RoutedEventArgs e)
    {
        await RunMaintenanceAsync(sender, "Clearing maintenance marker...", async () =>
            await ArcaneCommandRunner.RunAsync("--maintenance", "clear", "--reason", "gui-clear"));
    }

    private async void ListMaintenance_Click(object sender, RoutedEventArgs e)
    {
        await ListMaintenanceAsync(sender as Button);
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
        await RunMaintenanceAsync(sender, "Running elevated validation task...", async () =>
            await ArcaneScriptRunner.RunScriptAsync("run-admin-task.cmd", "ValidateAdmin"));
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

        await RunMaintenanceAsync(sender, "Installing or repairing service...", async () =>
            await ArcaneScriptRunner.RunScriptAsync(TimeSpan.FromMinutes(5), "run-admin-task.cmd", "InstallService"));
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

        await RunMaintenanceAsync(sender, "Installing or configuring Sysmon...", async () =>
            await ArcaneScriptRunner.RunScriptAsync(TimeSpan.FromMinutes(5), "run-admin-task.cmd", "InstallSysmon"));
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

        await RunMaintenanceAsync(sender, "Publishing binaries and restarting service...", async () =>
            await ArcaneScriptRunner.RunScriptAsync(TimeSpan.FromMinutes(5), "run-admin-task.cmd", "PublishRestart"));
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

        await RunMaintenanceAsync(sender, "Uninstalling service...", async () =>
            await ArcaneScriptRunner.RunScriptAsync(TimeSpan.FromMinutes(5), "run-admin-task.cmd", "UninstallService"));
    }

    private async void PollOnce_Click(object sender, RoutedEventArgs e)
    {
        await RunMaintenanceAsync(sender, "Running one detection poll...", async () =>
            await ArcaneCommandRunner.RunAsync(TimeSpan.FromMinutes(2), "--poll-once"));
    }

    private async void TestHealth_Click(object sender, RoutedEventArgs e)
    {
        await RunMaintenanceAsync(sender, "Sending health test...", async () =>
            await ArcaneCommandRunner.RunAsync("--test-health"));
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

        await RunMaintenanceAsync(sender, "Sending test alert...", async () =>
            await ArcaneCommandRunner.RunAsync("--test-alert"));
    }

    private async void PreviewAi_Click(object sender, RoutedEventArgs e)
    {
        await RunMaintenanceAsync(sender, "Building AI payload preview...", async () =>
            await ArcaneCommandRunner.RunAsync("--preview-ai-payload"));
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

        await RunMaintenanceAsync(sender, "Calling AI analysis provider...", async () =>
            await ArcaneCommandRunner.RunAsync(TimeSpan.FromMinutes(2), "--test-ai-analysis"));
    }

    private async void ResponseFirewall_Click(object sender, RoutedEventArgs e)
    {
        await RunMaintenanceAsync(sender, "Reading response firewall ledger...", async () =>
            await ArcaneCommandRunner.RunAsync("--response-firewall", "list"));
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

        await RunMaintenanceAsync(sender, "Clearing Arcane firewall rules...", async () =>
            await ArcaneCommandRunner.RunAsync("--response-firewall", "remove-all"));
    }

    private async void AgentActivity_Click(object sender, RoutedEventArgs e)
    {
        await RunMaintenanceAsync(sender, "Loading agent activity...", async () =>
            await ArcaneCommandRunner.RunAsync("--agent-activity", "--last", "24h"));
    }

    private async void Incidents_Click(object sender, RoutedEventArgs e)
    {
        await RunMaintenanceAsync(sender, "Loading recent incidents...", async () =>
            await ArcaneCommandRunner.RunAsync("--incidents", "--last", "24h"));
    }

    private async void SupportBundle_Click(object sender, RoutedEventArgs e)
    {
        await RunMaintenanceAsync(sender, "Creating support bundle...", async () =>
            await ArcaneCommandRunner.RunAsync(TimeSpan.FromMinutes(2), "--support-bundle"));
    }

    private async System.Threading.Tasks.Task ListMaintenanceAsync(Button? button = null)
    {
        await GuiCommandStatus.RunAsync(button, MaintenanceOutputText, "Loading maintenance markers...", async () =>
        {
            ArcaneCommandResult result = await ArcaneCommandRunner.RunAsync("--maintenance", "list", "--last", "24h");
            return result.CombinedText();
        });
    }

    private async System.Threading.Tasks.Task RunMaintenanceAsync(object sender, string status, Func<System.Threading.Tasks.Task<ArcaneCommandResult>> action)
    {
        await GuiCommandStatus.RunAsync(sender as Button, MaintenanceOutputText, status, async () =>
        {
            ArcaneCommandResult result = await action();
            return result.CombinedText();
        });
    }

}
