using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using ArcaneEDR_Gui.Services;

namespace ArcaneEDR_Gui.Pages;

public sealed partial class ConfigurationPage : Page
{
    private ArcaneConfigBundle? config;
    private bool loaded;

    public ConfigurationPage()
    {
        InitializeComponent();
        Loaded += async (_, _) =>
        {
            loaded = true;
            await RefreshAsync();
        };
    }

    private async void Validate_Click(object sender, RoutedEventArgs e)
    {
        await ValidateAsync(sender as Button);
    }

    private void OpenConfig_Click(object sender, RoutedEventArgs e)
    {
        ArcaneScriptRunner.OpenPath(ArcanePaths.Discover().ConfigFile);
    }

    private void OpenFolder_Click(object sender, RoutedEventArgs e)
    {
        string path = ArcanePaths.Discover().ConfigFile;
        ArcaneScriptRunner.OpenPath(Path.GetDirectoryName(path) ?? path);
    }

    private async void Help_Click(object sender, RoutedEventArgs e)
    {
        await GuiHelp.ShowAsync(
            XamlRoot,
            "Configuration help",
            "Guided settings cover the choices most operators need: alerting, enrichment, AI review, baseline tuning, response mode, and paths.\n\n" +
            "Advanced Keys edits the same config files directly. Use it when a setting is not surfaced in Guided yet.\n\n" +
            "Policy JSON controls narrow allow, suppress, raise, force, and tag decisions while preserving local evidence.\n\n" +
            "Saves create backups and run validation. Do not paste provider secrets into config; use environment variable names.");
    }

    private void OpenPolicy_Click(object sender, RoutedEventArgs e)
    {
        ArcaneScriptRunner.OpenPath(ArcanePaths.Discover().PolicyFile);
    }

    private async void SaveGuided_Click(object sender, RoutedEventArgs e)
    {
        if (config == null) return;

        if (GuidedSettingsEnableResponseRisk() &&
            !await GuiHelp.ConfirmRiskAsync(
                XamlRoot,
                "Enable response-capable settings?",
                "These settings can allow Arcane to block remote IPs, terminate processes, or evaluate those actions depending on the selected response mode.\n\n" +
                "Expected safe baseline: ResponseMode=AlertOnly with firewall and process termination response switches off.\n\n" +
                "Continue only if you intentionally want response-capable behavior and understand the rollback path in Maintenance.",
                "Save response settings"))
        {
            ValidationText.Text = "Save canceled. Response-capable settings were not written.";
            return;
        }

        ApplyGuidedToConfig(config);
        ValidationText.Text = config.Save();
        await RefreshAsync();
    }

    private async void SaveAdvanced_Click(object sender, RoutedEventArgs e)
    {
        if (config == null) return;

        ValidationText.Text = config.Save();
        await RefreshAsync();
    }

    private async void SavePolicy_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            ValidationText.Text = ArcanePolicyDocument.SaveFormatted(PolicyJsonText.Text);
            await ValidateAsync();
        }
        catch (Exception ex)
        {
            ValidationText.Text = "Policy JSON was not saved: " + ex.Message;
        }
    }

    private void FormatPolicy_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            PolicyJsonText.Text = ArcanePolicyDocument.Format(PolicyJsonText.Text);
        }
        catch (Exception ex)
        {
            ValidationText.Text = "Policy JSON could not be formatted: " + ex.Message;
        }
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
        ValidationText.Text = resetResult + Environment.NewLine + Environment.NewLine + ValidationText.Text;
    }

    private void ConfigFilter_Changed(object sender, RoutedEventArgs e)
    {
        if (!loaded) return;
        ApplyConfigFilters();
    }

    private void ConfigSearchBox_TextChanged(object sender, TextChangedEventArgs e)
    {
        if (!loaded) return;
        ApplyConfigFilters();
    }

    private async System.Threading.Tasks.Task RefreshAsync()
    {
        config = ArcaneConfigBundle.Load();
        LoadGuided(config);
        PopulateConfigCategories();
        ApplyConfigFilters();
        PolicyJsonText.Text = ArcanePolicyDocument.LoadText();
        await ValidateAsync();
    }

    private async System.Threading.Tasks.Task ValidateAsync(Button? button = null)
    {
        PathText.Text = ArcaneStateReader.BuildPathSummary();
        await GuiCommandStatus.RunAsync(button, ValidationText, "Validating configuration...", async () =>
        {
            ArcaneValidationReport validation = await ArcaneValidationView.RunAsync();
            return ArcaneValidationView.BuildOverviewText(validation);
        });
    }

    private void LoadGuided(ArcaneConfigBundle bundle)
    {
        SetCombo(ResponseModeBox, bundle.Runtime.Get("ResponseMode", "AlertOnly"));
        ResponseMinimumScoreBox.Text = bundle.Runtime.Get("ResponseMinimumScore", "95");
        FirewallResponseSwitch.IsOn = bundle.Runtime.GetBool("EnableFirewallBlockResponse", false);
        ProcessTerminationSwitch.IsOn = bundle.Runtime.GetBool("EnableProcessTerminationResponse", false);

        SetCombo(ExternalAlertProviderBox, bundle.Runtime.Get("ExternalAlertProvider", "Disabled"));
        MinimumEmailScoreBox.Text = bundle.Runtime.Get("MinimumEmailScore", "60");
        DailySummarySwitch.IsOn = bundle.Runtime.GetBool("EnableDailySummary", true);
        ServiceStartSwitch.IsOn = bundle.Runtime.GetBool("NotifyOnServiceStart", true);

        AIAnalysisSwitch.IsOn = bundle.Runtime.GetBool("EnableAIAnalysis", false);
        AIProviderBox.Text = bundle.Runtime.Get("AIAnalysisProviders", "OpenAI");
        AIModelBox.Text = bundle.Runtime.Get("AIAnalysisModel", "");
        AIEnvVarBox.Text = FirstNonEmpty(
            bundle.Runtime.Get("AIAnalysisApiKeyEnvironmentVariable", ""),
            bundle.Runtime.Get("AIAnalysisProviderApiKeyEnvironmentVariables", ""));

        CountryBlocksSwitch.IsOn = bundle.Runtime.GetBool("EnableRemoteEndpointCountryBlockEnrichment", false);
        RdapSwitch.IsOn = bundle.Runtime.GetBool("EnableRemoteEndpointRdapEnrichment", true);
        IpApiSwitch.IsOn = bundle.Runtime.GetBool("EnableRemoteEndpointIpApiGeolocation", false);
        IpWhoisSwitch.IsOn = bundle.Runtime.GetBool("EnableRemoteEndpointIpWhoisGeolocation", false);
        GeoMaxLookupsBox.Text = bundle.Runtime.Get("RemoteEndpointGeoProviderMaxLookupsPerPoll", "3");

        BaselineLearningSwitch.IsOn = bundle.Runtime.GetBool("BaselineLearningMode", true);
        AgentProcessNamesBox.Text = bundle.Runtime.Get("AgentProcessNames", "");
        AgentWorkspaceRootsBox.Text = bundle.Runtime.Get("AgentWorkspaceRoots", "");
        AgentPublishRootsBox.Text = bundle.Runtime.Get("AgentPublishRoots", "");

        LogDirectoryBox.Text = bundle.Runtime.Get("LogDirectory", "logs");
        PolicyFileBox.Text = bundle.Runtime.Get("PolicyFile", "arcane-policy.example.json");
        DestinationRootBox.Text = bundle.Deployment.Get("DestinationRoot", @"C:\Program Files");
        ExecutableNameBox.Text = bundle.Deployment.Get("ExecutableName", "ArcaneEDR.exe");
    }

    private void ApplyGuidedToConfig(ArcaneConfigBundle bundle)
    {
        bundle.SetEntry("Runtime", "ResponseMode", ComboText(ResponseModeBox, "AlertOnly"));
        bundle.SetEntry("Runtime", "ResponseMinimumScore", ResponseMinimumScoreBox.Text.Trim());
        bundle.SetEntry("Runtime", "EnableFirewallBlockResponse", BoolText(FirewallResponseSwitch.IsOn));
        bundle.SetEntry("Runtime", "EnableProcessTerminationResponse", BoolText(ProcessTerminationSwitch.IsOn));

        bundle.SetEntry("Runtime", "ExternalAlertProvider", ComboText(ExternalAlertProviderBox, "Disabled"));
        bundle.SetEntry("Runtime", "MinimumEmailScore", MinimumEmailScoreBox.Text.Trim());
        bundle.SetEntry("Runtime", "EnableDailySummary", BoolText(DailySummarySwitch.IsOn));
        bundle.SetEntry("Runtime", "NotifyOnServiceStart", BoolText(ServiceStartSwitch.IsOn));

        bundle.SetEntry("Runtime", "EnableAIAnalysis", BoolText(AIAnalysisSwitch.IsOn));
        bundle.SetEntry("Runtime", "AIAnalysisProviders", AIProviderBox.Text.Trim());
        bundle.SetEntry("Runtime", "AIAnalysisModel", AIModelBox.Text.Trim());
        bundle.SetEntry("Runtime", "AIAnalysisApiKeyEnvironmentVariable", AIEnvVarBox.Text.Trim());

        bundle.SetEntry("Runtime", "EnableRemoteEndpointCountryBlockEnrichment", BoolText(CountryBlocksSwitch.IsOn));
        bundle.SetEntry("Runtime", "EnableRemoteEndpointRdapEnrichment", BoolText(RdapSwitch.IsOn));
        bundle.SetEntry("Runtime", "EnableRemoteEndpointIpApiGeolocation", BoolText(IpApiSwitch.IsOn));
        bundle.SetEntry("Runtime", "EnableRemoteEndpointIpWhoisGeolocation", BoolText(IpWhoisSwitch.IsOn));
        bundle.SetEntry("Runtime", "RemoteEndpointGeoProviderMaxLookupsPerPoll", GeoMaxLookupsBox.Text.Trim());

        bundle.SetEntry("Runtime", "BaselineLearningMode", BoolText(BaselineLearningSwitch.IsOn));
        bundle.SetEntry("Runtime", "AgentProcessNames", AgentProcessNamesBox.Text.Trim());
        bundle.SetEntry("Runtime", "AgentWorkspaceRoots", AgentWorkspaceRootsBox.Text.Trim());
        bundle.SetEntry("Runtime", "AgentPublishRoots", AgentPublishRootsBox.Text.Trim());

        bundle.SetEntry("Runtime", "LogDirectory", LogDirectoryBox.Text.Trim());
        bundle.SetEntry("Runtime", "PolicyFile", PolicyFileBox.Text.Trim());
        bundle.SetEntry("Deployment", "DestinationRoot", DestinationRootBox.Text.Trim());
        bundle.SetEntry("Deployment", "ExecutableName", ExecutableNameBox.Text.Trim());
    }

    private bool GuidedSettingsEnableResponseRisk()
    {
        string responseMode = ComboText(ResponseModeBox, "AlertOnly");
        return !responseMode.Equals("AlertOnly", StringComparison.OrdinalIgnoreCase) ||
            FirewallResponseSwitch.IsOn ||
            ProcessTerminationSwitch.IsOn;
    }

    private void PopulateConfigCategories()
    {
        if (config == null) return;

        string selected = ComboText(ConfigCategoryFilterBox, "Any");
        ConfigCategoryFilterBox.Items.Clear();
        ConfigCategoryFilterBox.Items.Add(new ComboBoxItem { Content = "Any" });
        foreach (string category in config.Entries
            .Select(entry => entry.Category)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .OrderBy(category => category))
        {
            ConfigCategoryFilterBox.Items.Add(new ComboBoxItem { Content = category });
        }

        ConfigCategoryFilterBox.SelectedIndex = 0;
        for (int index = 0; index < ConfigCategoryFilterBox.Items.Count; index++)
        {
            if (ConfigCategoryFilterBox.Items[index] is ComboBoxItem item &&
                selected.Equals(item.Content?.ToString(), StringComparison.OrdinalIgnoreCase))
            {
                ConfigCategoryFilterBox.SelectedIndex = index;
                break;
            }
        }
    }

    private void ApplyConfigFilters()
    {
        if (config == null) return;

        IEnumerable<ArcaneConfigEntry> rows = config.Entries;
        string source = ComboText(ConfigSourceFilterBox, "Any");
        if (!source.Equals("Any", StringComparison.OrdinalIgnoreCase))
        {
            rows = rows.Where(entry => entry.Source.Equals(source, StringComparison.OrdinalIgnoreCase));
        }

        string category = ComboText(ConfigCategoryFilterBox, "Any");
        if (!category.Equals("Any", StringComparison.OrdinalIgnoreCase))
        {
            rows = rows.Where(entry => entry.Category.Equals(category, StringComparison.OrdinalIgnoreCase));
        }

        string search = ConfigSearchBox.Text.Trim();
        if (!String.IsNullOrWhiteSpace(search))
        {
            rows = rows.Where(entry =>
                Contains(entry.Key, search) ||
                Contains(entry.Value, search) ||
                Contains(entry.Category, search) ||
                Contains(entry.Description, search));
        }

        ConfigEntriesList.ItemsSource = rows
            .OrderBy(entry => entry.Source)
            .ThenBy(entry => entry.Category)
            .ThenBy(entry => entry.Key)
            .ToList();
    }

    private static string FirstNonEmpty(params string[] values)
    {
        return values.FirstOrDefault(value => !String.IsNullOrWhiteSpace(value)) ?? "";
    }

    private static string BoolText(bool value)
    {
        return value ? "true" : "false";
    }

    private static string ComboText(ComboBox comboBox, string fallback)
    {
        return (comboBox.SelectedItem as ComboBoxItem)?.Content?.ToString() ?? fallback;
    }

    private static void SetCombo(ComboBox comboBox, string value)
    {
        for (int index = 0; index < comboBox.Items.Count; index++)
        {
            if (comboBox.Items[index] is ComboBoxItem item &&
                value.Equals(item.Content?.ToString(), StringComparison.OrdinalIgnoreCase))
            {
                comboBox.SelectedIndex = index;
                return;
            }
        }

        comboBox.SelectedIndex = 0;
    }

    private static bool Contains(string value, string search)
    {
        return value.IndexOf(search, StringComparison.OrdinalIgnoreCase) >= 0;
    }
}
