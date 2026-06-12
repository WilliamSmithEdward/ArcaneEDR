using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using ArcaneEDR_Gui.Services;

namespace ArcaneEDR_Gui.Pages;

public sealed partial class PolicyPage : Page
{
    private ArcanePolicySnapshot? policy;
    private ArcanePolicyEntry? selectedEntry;
    private bool loaded;
    private bool fillingEditor;
    private bool restoringView;
    private string policySortKey = "order";
    private bool policySortAscending = true;

    public PolicyPage()
    {
        InitializeComponent();
        PopulateEditorScopes();
        RestorePolicyViewSettings();
        Loaded += async (_, _) =>
        {
            loaded = true;
            await RefreshPolicyAsync();
        };
    }

    private void PopulateEditorScopes()
    {
        PolicyEditorScopeBox.Items.Clear();
        foreach (PolicyScopeDefinition definition in PolicyScopeCatalog.AllAlphabetical())
        {
            ComboBoxItem item = new ComboBoxItem { Content = definition.DisplayName, Tag = definition.Scope };
            ToolTipService.SetToolTip(item, PolicyScopeCatalog.ScopeHelpText(definition.Scope));
            PolicyEditorScopeBox.Items.Add(item);
        }

        SetScopeCombo("Remote endpoint");
    }

    private async void Inspect_Click(object sender, RoutedEventArgs e)
    {
        await RefreshPolicyAsync(sender as Button);
        PolicyTabs.SelectedIndex = 1;
    }

    private async void Preview_Click(object sender, RoutedEventArgs e)
    {
        await GuiCommandStatus.RunAsync(sender as Button, PolicyOutputText, "Running policy preview...", async () =>
        {
            ArcaneCommandResult result = await ArcaneCommandRunner.RunAsync(
                "--policy-preview",
                "--sample-rule",
                "NET-BEACON-TIMING-LOW-RISK",
                "--sample-process",
                "codex.exe",
                "--sample-score",
                "55");
            return result.CombinedText();
        });
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
            "Entries is the friendly editor for the unified policy file. Use Add policy to create one policy entry, choose its type, then save.\n\n" +
            "Order is the file order within each policy type. Move up puts an entry earlier in that type. Network endpoint policy is first-match-wins; alert tuning applies every matching entry in order.\n\n" +
            "Static choices use dropdowns. Lists and maps still save as JSON values. Save creates a backup and validation output shows any blockers.");
    }

    private void PolicyFilter_Changed(object sender, RoutedEventArgs e)
    {
        if (!loaded) return;
        ApplyPolicyFilters();
        SavePolicyViewSettings();
    }

    private void PolicySearchBox_TextChanged(object sender, TextChangedEventArgs e)
    {
        if (!loaded) return;
        ApplyPolicyFilters();
    }

    private void SortOrder_Click(object sender, RoutedEventArgs e)
    {
        ChangePolicySort("order");
    }

    private void SortType_Click(object sender, RoutedEventArgs e)
    {
        ChangePolicySort("type");
    }

    private void SortPolicy_Click(object sender, RoutedEventArgs e)
    {
        ChangePolicySort("policy");
    }

    private void SortEnabled_Click(object sender, RoutedEventArgs e)
    {
        ChangePolicySort("enabled");
    }

    private void SortAction_Click(object sender, RoutedEventArgs e)
    {
        ChangePolicySort("action");
    }

    private void SortSummary_Click(object sender, RoutedEventArgs e)
    {
        ChangePolicySort("summary");
    }

    private void PolicyEntriesList_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (fillingEditor) return;
        ShowSelectedPolicyEntry(PolicyEntriesList.SelectedItem as ArcanePolicyEntry);
    }

    private void PolicyEditorScope_Changed(object sender, SelectionChangedEventArgs e)
    {
        if (fillingEditor) return;
        string scope = EditorScope();

        string currentAction = EditorAction();
        SetActionCombo(scope, String.IsNullOrWhiteSpace(currentAction) ? ArcanePolicyStore.DefaultActionForScope(scope) : currentAction);
        PolicyEditorPriorityText.Text = selectedEntry?.PriorityDisplay ?? "";

        UpdateEditorVisibility(scope);
    }

    private void PolicyEditorAction_Changed(object sender, SelectionChangedEventArgs e)
    {
        if (fillingEditor) return;
        UpdateActionDependentFields(EditorScope());
    }

    private void PolicyEditorExpirationDate_Changed(CalendarDatePicker sender, CalendarDatePickerDateChangedEventArgs args)
    {
        if (fillingEditor) return;
        UpdateEditorExpirationState();
    }

    private void PolicyEditorExpirationTime_Changed(object sender, TimePickerValueChangedEventArgs args)
    {
        if (fillingEditor) return;
        UpdateEditorExpirationState();
    }

    private void ClearEditorExpiration_Click(object sender, RoutedEventArgs e)
    {
        SetEditorExpiration("");
        PolicyEditorStatusText.Text = "Expiration cleared.";
    }

    private async void AddPolicy_Click(object sender, RoutedEventArgs e)
    {
        PolicyWizardResult result = await PolicyWizard.ShowAsync(XamlRoot, null);
        if (result.Saved)
        {
            await RefreshPolicyAfterMutationAsync(result.Scope, result.Id, result.Status, sender as Button);
        }
    }

    private async void SavePolicyEntry_Click(object sender, RoutedEventArgs e)
    {
        await SavePolicyEntryAsync(sender as Button);
    }

    private async void DeletePolicyEntry_Click(object sender, RoutedEventArgs e)
    {
        if (selectedEntry == null)
        {
            PolicyEditorStatusText.Text = "No saved policy entry selected.";
            return;
        }

        if (!await GuiHelp.ConfirmRiskAsync(
            XamlRoot,
            "Delete policy entry?",
            "This removes the selected entry from the unified policy file and creates a backup before saving.\n\n" +
            "Deleting policy entries can change alert volume, response behavior, or local allow/block decisions.",
            "Delete policy"))
        {
            PolicyEditorStatusText.Text = "Delete canceled.";
            return;
        }

        try
        {
            string result = ArcanePolicyStore.DeleteEntry(selectedEntry);
            selectedEntry = null;
            await RefreshPolicyAfterMutationAsync("", "", result, sender as Button);
        }
        catch (Exception ex)
        {
            GuiDiagnostics.LogException("policy-delete", ex);
            PolicyEditorStatusText.Text = "Delete failed: " + ex.Message;
        }
    }

    private async void MoveHigher_Click(object sender, RoutedEventArgs e)
    {
        await MoveSelectedPolicyAsync(-1);
    }

    private async void MoveLower_Click(object sender, RoutedEventArgs e)
    {
        await MoveSelectedPolicyAsync(1);
    }

    private void FormatMatch_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            if (ArcanePolicyStore.IsRuleScope(EditorScope()))
            {
                PolicyEditorMatchJsonBox.Text = ArcanePolicyStore.FormatMatchJson(PolicyEditorMatchJsonBox.Text);
                PolicyEditorStatusText.Text = "Formatted match JSON.";
            }
            else
            {
                PolicyEditorSettingValueBox.Text = ArcanePolicyDocument.Format(PolicyEditorSettingValueBox.Text);
                PolicyEditorStatusText.Text = "Formatted value JSON.";
            }
        }
        catch (Exception ex)
        {
            PolicyEditorStatusText.Text = "JSON could not be formatted: " + ex.Message;
        }
    }

    private async System.Threading.Tasks.Task RefreshPolicyAsync(Button? button = null, string selectScope = "", string selectId = "")
    {
        string selectedScope = String.IsNullOrWhiteSpace(selectScope) ? selectedEntry?.Scope ?? "" : selectScope;
        string selectedId = String.IsNullOrWhiteSpace(selectId) ? selectedEntry?.Id ?? "" : selectId;

        policy = ArcanePolicyStore.Load();
        PolicyPathText.Text = policy.Path;
        PolicyLoadStatusText.Text = policy.LoadStatus;
        PolicyRuleCountText.Text = policy.SummaryText;
        PolicyCountryCountText.Text = AllowedCountryCount(policy).ToString(CultureInfo.InvariantCulture);
        PolicyRawText.Text = String.IsNullOrWhiteSpace(policy.RawJson) ? policy.LoadStatus : policy.RawJson;

        PopulatePolicyScopes();
        ApplyPolicyFilters(selectedScope, selectedId);
        await InspectAsync(button);
    }

    private async System.Threading.Tasks.Task InspectAsync(Button? button = null)
    {
        await GuiCommandStatus.RunAsync(button, PolicyOutputText, "Inspecting policy...", async () =>
        {
            ArcaneCommandResult result = await ArcaneCommandRunner.RunAsync("--policy-inspect");
            return result.CombinedText();
        });
    }

    private void PopulatePolicyScopes()
    {
        if (policy == null) return;

        string selected = ComboText(PolicyScopeFilterBox, "Any");
        PolicyScopeFilterBox.Items.Clear();
        PolicyScopeFilterBox.Items.Add(new ComboBoxItem { Content = "Any", Tag = "Any" });

        foreach (string scope in policy.Entries
            .Select(entry => entry.Scope)
            .Where(scope => !String.IsNullOrWhiteSpace(scope))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .OrderBy(PolicyScopeCatalog.DisplayNameForScope, StringComparer.OrdinalIgnoreCase))
        {
            ComboBoxItem item = new ComboBoxItem { Content = PolicyScopeCatalog.DisplayNameForScope(scope), Tag = scope };
            ToolTipService.SetToolTip(item, PolicyScopeCatalog.ScopeHelpText(scope));
            PolicyScopeFilterBox.Items.Add(item);
        }

        PolicyScopeFilterBox.SelectedIndex = 0;
        for (int index = 0; index < PolicyScopeFilterBox.Items.Count; index++)
        {
            if (PolicyScopeFilterBox.Items[index] is ComboBoxItem item &&
                selected.Equals(ComboItemValue(item), StringComparison.OrdinalIgnoreCase))
            {
                PolicyScopeFilterBox.SelectedIndex = index;
                break;
            }
        }
    }

    private void ApplyPolicyFilters(string selectScope = "", string selectId = "")
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

        if (PolicyHideDisabledBox.IsChecked == true)
        {
            rows = rows.Where(entry => entry.Enabled);
        }

        List<ArcanePolicyEntry> visible = SortPolicyEntries(rows).ToList();
        UpdateSortIndicators();

        fillingEditor = true;
        try
        {
            PolicyEntriesList.ItemsSource = visible;
            int selectedIndex = -1;
            if (!String.IsNullOrWhiteSpace(selectId))
            {
                selectedIndex = visible.FindIndex(entry =>
                    entry.Scope.Equals(selectScope, StringComparison.OrdinalIgnoreCase) &&
                    entry.Id.Equals(selectId, StringComparison.OrdinalIgnoreCase));
            }

            PolicyEntriesList.SelectedIndex = selectedIndex >= 0 ? selectedIndex : (visible.Count == 0 ? -1 : 0);
        }
        finally
        {
            fillingEditor = false;
        }

        ShowSelectedPolicyEntry(PolicyEntriesList.SelectedItem as ArcanePolicyEntry);
    }

    private void RestorePolicyViewSettings()
    {
        restoringView = true;
        try
        {
            PolicyHideDisabledBox.IsChecked = GuiStartupSettings.Load().PolicyHideDisabled;
        }
        finally
        {
            restoringView = false;
        }
    }

    private void SavePolicyViewSettings()
    {
        if (restoringView) return;

        GuiUserSettings settings = GuiStartupSettings.Load();
        settings.PolicyHideDisabled = PolicyHideDisabledBox.IsChecked == true;
        GuiStartupSettings.SaveAndApply(settings);
    }

    private void ShowSelectedPolicyEntry(ArcanePolicyEntry? entry)
    {
        selectedEntry = entry;

        if (entry == null)
        {
            ClearEditor("No policy entry selected", "Choose or create a policy entry.");
            return;
        }

        fillingEditor = true;
        try
        {
            PolicyEditorTitleText.Text = entry.TypeDisplay + " / " + entry.Id;
            PolicyEditorModeText.Text = "Editing order " + entry.PriorityDisplay + " from unified policy";
            SetScopeCombo(entry.Scope);
            PolicyEditorPriorityText.Text = entry.PriorityDisplay;
            PolicyEditorIdBox.Text = entry.Id;
            PolicyEditorEnabledSwitch.IsOn = entry.Enabled;
            SetActionCombo(entry.Scope, entry.Action);
            PolicyEditorScoreBox.Text = entry.Score;
            PolicyEditorScoreDeltaBox.Text = entry.ScoreDelta;
            PolicyEditorOwnerBox.Text = entry.Owner;
            PolicyEditorTagBox.Text = entry.Tag;
            SetEditorExpiration(entry.ExpiresUtc);
            PolicyEditorReasonBox.Text = entry.Reason;
            PolicyEditorMatchJsonBox.Text = String.IsNullOrWhiteSpace(entry.MatchJson) ? "{}" : entry.MatchJson;
            PolicyEditorSettingValueBox.Text = String.IsNullOrWhiteSpace(entry.ValueJson) ? "[]" : entry.ValueJson;
            SelectedPolicyDetailText.Text = entry.DetailText;
            PolicyEditorStatusText.Text = "Order is " + entry.PriorityDisplay + ". Move up/down changes file order within this policy type.";
        }
        finally
        {
            fillingEditor = false;
        }

        UpdateEditorVisibility(entry.Scope);
    }

    private void ClearEditor(string title, string detail)
    {
        fillingEditor = true;
        try
        {
            PolicyEditorTitleText.Text = title;
            PolicyEditorModeText.Text = detail;
            SetScopeCombo("Remote endpoint");
            PolicyEditorPriorityText.Text = "";
            PolicyEditorIdBox.Text = "";
            PolicyEditorEnabledSwitch.IsOn = true;
            SetActionCombo("Remote endpoint", "");
            PolicyEditorScoreBox.Text = "";
            PolicyEditorScoreDeltaBox.Text = "";
            PolicyEditorOwnerBox.Text = "";
            PolicyEditorTagBox.Text = "";
            SetEditorExpiration("");
            PolicyEditorReasonBox.Text = "";
            PolicyEditorMatchJsonBox.Text = "{}";
            PolicyEditorSettingValueBox.Text = "[]";
            SelectedPolicyDetailText.Text = "";
            PolicyOrderHintText.Text = "";
            PolicyEditorStatusText.Text = "No policy changes pending.";
        }
        finally
        {
            fillingEditor = false;
        }

        UpdateEditorVisibility("Remote endpoint");
    }

    private async System.Threading.Tasks.Task SavePolicyEntryAsync(Button? button)
    {
        if (selectedEntry == null)
        {
            PolicyEditorStatusText.Text = "Select a saved policy entry to edit, or use Add policy to create one.";
            return;
        }

        ArcanePolicyEditRequest request = BuildEditRequest();
        string mutationStatus = "";

        await GuiCommandStatus.RunAsync(button, PolicyEditorStatusText, "Saving policy...", async () =>
        {
            string saveResult = ArcanePolicyStore.SaveEdit(request);
            ArcaneValidationReport validation = await ArcaneValidationView.RunAsync();
            mutationStatus = saveResult + Environment.NewLine + ArcaneValidationView.Heading(validation) + Environment.NewLine +
                ArcaneValidationView.BuildOverviewText(validation);
            return mutationStatus;
        });

        string scope = request.Scope;
        string id = request.Id;
        await RefreshPolicyAfterMutationAsync(scope, id, mutationStatus, null);
    }

    private async System.Threading.Tasks.Task RefreshPolicyAfterMutationAsync(string scope, string id, string status, Button? button)
    {
        await RefreshPolicyAsync(button, scope, id);
        if (!String.IsNullOrWhiteSpace(scope) && !String.IsNullOrWhiteSpace(id))
        {
            SelectPolicyEntry(scope, id);
        }

        if (!String.IsNullOrWhiteSpace(status))
        {
            PolicyEditorStatusText.Text = status;
        }
    }

    private ArcanePolicyEditRequest BuildEditRequest()
    {
        if (selectedEntry == null)
        {
            throw new InvalidOperationException("Select a saved policy entry to edit, or use Add policy to create one.");
        }

        string scope = EditorScope();
        bool isRule = ArcanePolicyStore.IsRuleScope(scope);
        return new ArcanePolicyEditRequest
        {
            Scope = scope,
            SectionName = FirstNonEmpty(selectedEntry.SectionName, ArcanePolicyStore.SectionNameForScope(scope)),
            IsRule = isRule,
            IsNew = false,
            RuleIndex = selectedEntry.RuleIndex,
            OriginalId = selectedEntry.Id,
            Id = PolicyEditorIdBox.Text.Trim(),
            Enabled = PolicyEditorEnabledSwitch.IsOn,
            Action = EditorAction(),
            Score = PolicyEditorScoreBox.Text.Trim(),
            ScoreDelta = PolicyEditorScoreDeltaBox.Text.Trim(),
            Owner = PolicyEditorOwnerBox.Text.Trim(),
            Tag = PolicyEditorTagBox.Text.Trim(),
            ExpiresUtc = FormatEditorExpirationUtc(),
            Reason = PolicyEditorReasonBox.Text.Trim(),
            MatchJson = PolicyEditorMatchJsonBox.Text.Trim(),
            ValueJson = PolicyEditorSettingValueBox.Text.Trim()
        };
    }

    private async System.Threading.Tasks.Task MoveSelectedPolicyAsync(int delta)
    {
        if (selectedEntry == null)
        {
            PolicyEditorStatusText.Text = "Select a policy entry to change order.";
            return;
        }

        try
        {
            string scope = selectedEntry.Scope;
            string id = selectedEntry.Id;
            policySortKey = "order";
            policySortAscending = true;
            string result = ArcanePolicyStore.MoveEntry(selectedEntry, delta);
            await RefreshPolicyAfterMutationAsync(scope, id, result, null);
        }
        catch (Exception ex)
        {
            GuiDiagnostics.LogException("policy-move", ex);
            PolicyEditorStatusText.Text = "Order move failed: " + ex.Message;
        }
    }

    private void SelectPolicyEntry(string scope, string id)
    {
        if (PolicyEntriesList.ItemsSource is not IEnumerable<ArcanePolicyEntry> rows)
        {
            return;
        }

        ArcanePolicyEntry? match = rows.FirstOrDefault(entry =>
            entry.Scope.Equals(scope, StringComparison.OrdinalIgnoreCase) &&
            entry.Id.Equals(id, StringComparison.OrdinalIgnoreCase));
        if (match != null)
        {
            PolicyEntriesList.SelectedItem = match;
            ShowSelectedPolicyEntry(match);
        }
    }

    private void UpdateEditorVisibility(string scope)
    {
        bool isRule = ArcanePolicyStore.IsRuleScope(scope);
        bool hasSelection = selectedEntry != null;
        ToolTipService.SetToolTip(PolicyEditorScopeBox, PolicyScopeCatalog.ScopeHelpText(scope));
        RuleEditorPanel.Visibility = isRule ? Visibility.Visible : Visibility.Collapsed;
        SettingEditorPanel.Visibility = isRule ? Visibility.Collapsed : Visibility.Visible;
        FormatMatchButton.IsEnabled = hasSelection;
        MoveHigherButton.IsEnabled = hasSelection;
        MoveLowerButton.IsEnabled = hasSelection;
        EditorMoveHigherButton.IsEnabled = hasSelection;
        EditorMoveLowerButton.IsEnabled = hasSelection;
        SavePolicyEntryButton.IsEnabled = hasSelection;
        DeletePolicyEntryButton.IsEnabled = hasSelection;
        PolicyEditorScopeBox.IsEnabled = false;
        PolicyEditorEnabledSwitch.Visibility = isRule ? Visibility.Visible : Visibility.Collapsed;
        PolicyEditorEnabledSwitch.IsEnabled = hasSelection && isRule;
        PolicyEditorActionBox.IsEnabled = hasSelection && isRule;
        bool isDetection = scope.Equals("Detection", StringComparison.OrdinalIgnoreCase);
        DetectionMetadataPanel.Visibility = isDetection ? Visibility.Visible : Visibility.Collapsed;
        PolicyEditorOwnerBox.IsEnabled = hasSelection && isDetection;
        PolicyEditorTagBox.IsEnabled = hasSelection && isDetection;
        PolicyEditorExpiresDatePicker.IsEnabled = hasSelection && isDetection;
        PolicyEditorExpiresTimePicker.IsEnabled = hasSelection && isDetection && PolicyEditorExpiresDatePicker.Date.HasValue;
        PolicyEditorClearExpiresButton.IsEnabled = hasSelection && isDetection && PolicyEditorExpiresDatePicker.Date.HasValue;
        PolicyOrderHintText.Text = OrderHintText(scope);
        UpdateActionDependentFields(scope);
    }

    private void SetEditorExpiration(string expiresUtc)
    {
        fillingEditor = true;
        try
        {
            if (DateTimeOffset.TryParse(expiresUtc, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out DateTimeOffset parsed))
            {
                PolicyEditorExpiresDatePicker.Date = new DateTimeOffset(parsed.Year, parsed.Month, parsed.Day, 0, 0, 0, TimeSpan.Zero);
                PolicyEditorExpiresTimePicker.Time = parsed.TimeOfDay;
            }
            else
            {
                PolicyEditorExpiresDatePicker.Date = null;
                PolicyEditorExpiresTimePicker.Time = TimeSpan.Zero;
            }
        }
        finally
        {
            fillingEditor = false;
        }

        PolicyEditorExpiresTimePicker.IsEnabled = selectedEntry != null &&
            selectedEntry.Scope.Equals("Detection", StringComparison.OrdinalIgnoreCase) &&
            PolicyEditorExpiresDatePicker.Date.HasValue;
        PolicyEditorClearExpiresButton.IsEnabled = selectedEntry != null &&
            selectedEntry.Scope.Equals("Detection", StringComparison.OrdinalIgnoreCase) &&
            PolicyEditorExpiresDatePicker.Date.HasValue;
    }

    private void UpdateEditorExpirationState()
    {
        bool hasExpiration = PolicyEditorExpiresDatePicker.Date.HasValue;
        bool isDetection = selectedEntry != null && selectedEntry.Scope.Equals("Detection", StringComparison.OrdinalIgnoreCase);
        PolicyEditorExpiresTimePicker.IsEnabled = isDetection && hasExpiration;
        PolicyEditorClearExpiresButton.IsEnabled = isDetection && hasExpiration;
        string formatted = FormatEditorExpirationUtc();
        PolicyEditorStatusText.Text = String.IsNullOrWhiteSpace(formatted)
            ? "No expiration selected."
            : "Expiration set to " + formatted + ".";
    }

    private string FormatEditorExpirationUtc()
    {
        DateTimeOffset? date = PolicyEditorExpiresDatePicker.Date;
        if (!date.HasValue)
        {
            return "";
        }

        DateTimeOffset utc = new DateTimeOffset(
            date.Value.Year,
            date.Value.Month,
            date.Value.Day,
            PolicyEditorExpiresTimePicker.Time.Hours,
            PolicyEditorExpiresTimePicker.Time.Minutes,
            0,
            TimeSpan.Zero);
        return utc.ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", CultureInfo.InvariantCulture);
    }

    private void UpdateActionDependentFields(string scope)
    {
        string action = EditorAction();
        bool isRule = ArcanePolicyStore.IsRuleScope(scope);
        bool hasSelection = selectedEntry != null;
        bool scoreRelevant = hasSelection && isRule && PolicyScopeCatalog.IsScoreRelevant(scope, action);
        bool deltaRelevant = hasSelection && isRule && PolicyScopeCatalog.IsDeltaRelevant(scope, action);

        PolicyEditorScoreBox.IsEnabled = scoreRelevant;
        PolicyEditorScoreDeltaBox.IsEnabled = deltaRelevant;
        PolicyScoreHintText.Text = isRule ? PolicyScopeCatalog.ScoreHintText(scope, action) : "";

        ToolTipService.SetToolTip(PolicyEditorActionBox, PolicyScopeCatalog.ActionHelpText(scope, action));
        ToolTipService.SetToolTip(PolicyEditorScoreBox, PolicyScopeCatalog.ScoreToolTipText(scope, action));
        ToolTipService.SetToolTip(PolicyEditorScoreDeltaBox, PolicyScopeCatalog.DeltaToolTipText(scope, action));
    }

    private void SetScopeCombo(string scope)
    {
        for (int index = 0; index < PolicyEditorScopeBox.Items.Count; index++)
        {
            if (PolicyEditorScopeBox.Items[index] is ComboBoxItem item &&
                scope.Equals(ComboItemValue(item), StringComparison.OrdinalIgnoreCase))
            {
                PolicyEditorScopeBox.SelectedIndex = index;
                return;
            }
        }

        PolicyEditorScopeBox.SelectedIndex = 0;
    }

    private void SetActionCombo(string scope, string action)
    {
        string selected = String.IsNullOrWhiteSpace(action) ? ArcanePolicyStore.DefaultActionForScope(scope) : action.Trim();
        PolicyEditorActionBox.Items.Clear();

        int selectedIndex = -1;
        IReadOnlyList<string> actions = ArcanePolicyStore.ActionsForScope(scope);
        for (int index = 0; index < actions.Count; index++)
        {
            string value = actions[index];
            ComboBoxItem item = new ComboBoxItem { Content = value };
            ToolTipService.SetToolTip(item, PolicyScopeCatalog.ActionHelpText(scope, value));
            PolicyEditorActionBox.Items.Add(item);
            if (value.Equals(selected, StringComparison.OrdinalIgnoreCase))
            {
                selectedIndex = index;
            }
        }

        if (selectedIndex < 0)
        {
            string fallback = ArcanePolicyStore.DefaultActionForScope(scope);
            for (int index = 0; index < PolicyEditorActionBox.Items.Count; index++)
            {
                if (PolicyEditorActionBox.Items[index] is ComboBoxItem item &&
                    fallback.Equals(item.Content?.ToString(), StringComparison.OrdinalIgnoreCase))
                {
                    selectedIndex = index;
                    break;
                }
            }
        }

        PolicyEditorActionBox.SelectedIndex = selectedIndex >= 0 ? selectedIndex : 0;
    }

    private string EditorScope()
    {
        return ComboText(PolicyEditorScopeBox, "Remote endpoint");
    }

    private string EditorAction()
    {
        return ComboText(PolicyEditorActionBox, ArcanePolicyStore.DefaultActionForScope(EditorScope()));
    }

    private void ChangePolicySort(string key)
    {
        string selectedScope = selectedEntry?.Scope ?? "";
        string selectedId = selectedEntry?.Id ?? "";
        if (policySortKey.Equals(key, StringComparison.OrdinalIgnoreCase))
        {
            policySortAscending = !policySortAscending;
        }
        else
        {
            policySortKey = key;
            policySortAscending = true;
        }

        ApplyPolicyFilters(selectedScope, selectedId);
    }

    private IEnumerable<ArcanePolicyEntry> SortPolicyEntries(IEnumerable<ArcanePolicyEntry> rows)
    {
        IOrderedEnumerable<ArcanePolicyEntry> ordered;
        if (policySortKey.Equals("type", StringComparison.OrdinalIgnoreCase))
        {
            ordered = policySortAscending
                ? rows.OrderBy(entry => entry.TypeDisplay, StringComparer.OrdinalIgnoreCase)
                : rows.OrderByDescending(entry => entry.TypeDisplay, StringComparer.OrdinalIgnoreCase);
        }
        else if (policySortKey.Equals("policy", StringComparison.OrdinalIgnoreCase))
        {
            ordered = policySortAscending
                ? rows.OrderBy(entry => entry.Id, StringComparer.OrdinalIgnoreCase)
                : rows.OrderByDescending(entry => entry.Id, StringComparer.OrdinalIgnoreCase);
        }
        else if (policySortKey.Equals("enabled", StringComparison.OrdinalIgnoreCase))
        {
            ordered = policySortAscending
                ? rows.OrderBy(entry => entry.Enabled)
                : rows.OrderByDescending(entry => entry.Enabled);
        }
        else if (policySortKey.Equals("action", StringComparison.OrdinalIgnoreCase))
        {
            ordered = policySortAscending
                ? rows.OrderBy(entry => entry.Action, StringComparer.OrdinalIgnoreCase)
                : rows.OrderByDescending(entry => entry.Action, StringComparer.OrdinalIgnoreCase);
        }
        else if (policySortKey.Equals("summary", StringComparison.OrdinalIgnoreCase))
        {
            ordered = policySortAscending
                ? rows.OrderBy(entry => entry.Reason, StringComparer.OrdinalIgnoreCase).ThenBy(entry => entry.MatchSummary, StringComparer.OrdinalIgnoreCase)
                : rows.OrderByDescending(entry => entry.Reason, StringComparer.OrdinalIgnoreCase).ThenByDescending(entry => entry.MatchSummary, StringComparer.OrdinalIgnoreCase);
        }
        else
        {
            ordered = policySortAscending
                ? rows.OrderBy(entry => entry.PrioritySort)
                : rows.OrderByDescending(entry => entry.PrioritySort);
        }

        return ordered
            .ThenBy(entry => PolicyScopeCatalog.SortOrder(entry.Scope))
            .ThenBy(entry => entry.SectionIndex)
            .ThenBy(entry => entry.Id, StringComparer.OrdinalIgnoreCase);
    }

    private void UpdateSortIndicators()
    {
        SortOrderIndicator.Text = SortIndicator("order");
        SortTypeIndicator.Text = SortIndicator("type");
        SortPolicyIndicator.Text = SortIndicator("policy");
        SortEnabledIndicator.Text = SortIndicator("enabled");
        SortActionIndicator.Text = SortIndicator("action");
        SortSummaryIndicator.Text = SortIndicator("summary");
    }

    private string SortIndicator(string key)
    {
        if (!policySortKey.Equals(key, StringComparison.OrdinalIgnoreCase)) return "";
        return policySortAscending ? "^" : "v";
    }

    private string OrderHintText(string scope)
    {
        if (selectedEntry == null)
        {
            return "Select a policy entry to edit it.";
        }

        return "Order " + selectedEntry.PriorityDisplay + " in " + PolicyScopeCatalog.DisplayNameForScope(scope) + ". Move up/down changes file order within that policy type.";
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
        return comboBox.SelectedItem is ComboBoxItem item ? ComboItemValue(item) : fallback;
    }

    private static string ComboItemValue(ComboBoxItem item)
    {
        string? tag = item.Tag?.ToString();
        if (!String.IsNullOrWhiteSpace(tag))
        {
            return tag;
        }

        return item.Content?.ToString() ?? "";
    }

    private static string FirstNonEmpty(params string?[] values)
    {
        foreach (string? value in values)
        {
            if (!String.IsNullOrWhiteSpace(value))
            {
                return value;
            }
        }

        return "";
    }
}
