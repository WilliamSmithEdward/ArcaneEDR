using System;
using System.Collections.Generic;
using System.Linq;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using ArcaneEDR_Gui.Services;

namespace ArcaneEDR_Gui.Pages;

public sealed partial class PolicyPage : Page
{
    private ArcanePolicySnapshot? policy;
    private bool loaded;

    public PolicyPage()
    {
        InitializeComponent();
        Loaded += async (_, _) =>
        {
            loaded = true;
            await RefreshPolicyAsync();
        };
    }

    private async void Inspect_Click(object sender, RoutedEventArgs e)
    {
        await RefreshPolicyAsync();
        PolicyTabs.SelectedIndex = 1;
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
        PolicyTabs.SelectedIndex = 1;
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
            "Entries shows the actual unified policy file Arcane is using: allowlists, blocklists, response gates, remote endpoint rules, and detection tuning rules.\n\n" +
            "Use Search to find a carried-over local rule, trusted company, allowed country, process name, or action such as suppress_external, trust, critical, or block.\n\n" +
            "Inspect Output is the validator-style summary. Raw JSON shows the file content. Configuration > Policy JSON is the editable view.");
    }

    private void PolicyFilter_Changed(object sender, RoutedEventArgs e)
    {
        if (!loaded) return;
        ApplyPolicyFilters();
    }

    private void PolicySearchBox_TextChanged(object sender, TextChangedEventArgs e)
    {
        if (!loaded) return;
        ApplyPolicyFilters();
    }

    private void PolicyEntriesList_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        ShowSelectedPolicyEntry(PolicyEntriesList.SelectedItem as ArcanePolicyEntry);
    }

    private async System.Threading.Tasks.Task RefreshPolicyAsync()
    {
        policy = ArcanePolicyStore.Load();
        PolicyPathText.Text = policy.Path;
        PolicyLoadStatusText.Text = policy.LoadStatus;
        PolicyRuleCountText.Text = policy.SummaryText;
        PolicyCountryCountText.Text = AllowedCountryCount(policy).ToString(System.Globalization.CultureInfo.InvariantCulture);
        PolicyRawText.Text = String.IsNullOrWhiteSpace(policy.RawJson) ? policy.LoadStatus : policy.RawJson;

        PopulatePolicyScopes();
        ApplyPolicyFilters();
        await InspectAsync();
    }

    private async System.Threading.Tasks.Task InspectAsync()
    {
        ArcaneCommandResult result = await ArcaneCommandRunner.RunAsync("--policy-inspect");
        PolicyOutputText.Text = result.CombinedText();
    }

    private void PopulatePolicyScopes()
    {
        if (policy == null) return;

        string selected = ComboText(PolicyScopeFilterBox, "Any");
        PolicyScopeFilterBox.Items.Clear();
        PolicyScopeFilterBox.Items.Add(new ComboBoxItem { Content = "Any" });

        foreach (string scope in policy.Entries
            .Select(entry => entry.Scope)
            .Where(scope => !String.IsNullOrWhiteSpace(scope))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .OrderBy(scope => scope))
        {
            PolicyScopeFilterBox.Items.Add(new ComboBoxItem { Content = scope });
        }

        PolicyScopeFilterBox.SelectedIndex = 0;
        for (int index = 0; index < PolicyScopeFilterBox.Items.Count; index++)
        {
            if (PolicyScopeFilterBox.Items[index] is ComboBoxItem item &&
                selected.Equals(item.Content?.ToString(), StringComparison.OrdinalIgnoreCase))
            {
                PolicyScopeFilterBox.SelectedIndex = index;
                break;
            }
        }
    }

    private void ApplyPolicyFilters()
    {
        if (policy == null) return;

        IEnumerable<ArcanePolicyEntry> rows = policy.Entries;
        string scope = ComboText(PolicyScopeFilterBox, "Any");
        if (!scope.Equals("Any", StringComparison.OrdinalIgnoreCase))
        {
            rows = rows.Where(entry => entry.Scope.Equals(scope, StringComparison.OrdinalIgnoreCase));
        }

        string search = PolicySearchBox.Text.Trim().ToLowerInvariant();
        if (!String.IsNullOrWhiteSpace(search))
        {
            rows = rows.Where(entry => entry.SearchText.Contains(search, StringComparison.OrdinalIgnoreCase));
        }

        List<ArcanePolicyEntry> visible = rows
            .OrderBy(entry => ScopeOrder(entry.Scope))
            .ThenBy(entry => entry.Id)
            .ToList();

        PolicyEntriesList.ItemsSource = visible;
        PolicyEntriesList.SelectedIndex = visible.Count == 0 ? -1 : 0;
        ShowSelectedPolicyEntry(visible.Count == 0 ? null : visible[0]);
    }

    private void ShowSelectedPolicyEntry(ArcanePolicyEntry? entry)
    {
        if (entry == null)
        {
            SelectedPolicyTitleText.Text = "No policy entry selected";
            SelectedPolicyDetailText.Text = "No entries match the current filter.";
            return;
        }

        SelectedPolicyTitleText.Text = entry.Scope + " / " + entry.Id;
        SelectedPolicyDetailText.Text = entry.DetailText;
    }

    private static int ScopeOrder(string scope)
    {
        return scope switch
        {
            "Allowlist" => 0,
            "Blocklist" => 1,
            "Response" => 2,
            "Remote endpoint" => 3,
            "Detection" => 4,
            _ => 10
        };
    }

    private static int AllowedCountryCount(ArcanePolicySnapshot snapshot)
    {
        ArcanePolicyEntry? countries = snapshot.Entries.FirstOrDefault(entry =>
            entry.Scope.Equals("Allowlist", StringComparison.OrdinalIgnoreCase) &&
            entry.Id.Equals("allowed_remote_countries", StringComparison.OrdinalIgnoreCase));
        if (countries == null || String.IsNullOrWhiteSpace(countries.MatchSummary))
        {
            return 0;
        }

        return countries.ItemCount;
    }

    private static string ComboText(ComboBox comboBox, string fallback)
    {
        return (comboBox.SelectedItem as ComboBoxItem)?.Content?.ToString() ?? fallback;
    }
}
