using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Text.Json;
using System.Threading.Tasks;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;

namespace ArcaneEDR_Gui.Services;

internal sealed class PolicyWizardResult
{
    public bool Saved { get; set; }
    public string Scope { get; set; } = "";
    public string Id { get; set; } = "";
    public string Status { get; set; } = "";
}

internal sealed class PolicyWizardFieldChoice
{
    public string Label { get; set; } = "";
    public string NetworkField { get; set; } = "";
    public string DetectionField { get; set; } = "";
    public string InitialValue { get; set; } = "";
    public IReadOnlyList<string> Options { get; set; } = Array.Empty<string>();
    public bool DefaultNetwork { get; set; }
    public bool DefaultDetection { get; set; }
    public string Help { get; set; } = "";
    public CheckBox? CheckBox { get; set; }
    public TextBox? ValueBox { get; set; }
    public ComboBox? ValueComboBox { get; set; }

    public bool AppliesTo(string scope)
    {
        return scope.Equals("Remote endpoint", StringComparison.OrdinalIgnoreCase)
            ? !String.IsNullOrWhiteSpace(NetworkField)
            : scope.Equals("Detection", StringComparison.OrdinalIgnoreCase) && !String.IsNullOrWhiteSpace(DetectionField);
    }

    public string FieldForScope(string scope)
    {
        return scope.Equals("Remote endpoint", StringComparison.OrdinalIgnoreCase) ? NetworkField : DetectionField;
    }

    public bool DefaultForScope(string scope)
    {
        return scope.Equals("Remote endpoint", StringComparison.OrdinalIgnoreCase) ? DefaultNetwork : DefaultDetection;
    }

    public string Value()
    {
        if (ValueBox != null)
        {
            return ValueBox.Text.Trim();
        }

        if (ValueComboBox?.SelectedItem is ComboBoxItem item)
        {
            return item.Content?.ToString()?.Trim() ?? "";
        }

        return "";
    }
}

internal static class PolicyWizard
{
    public static async Task<PolicyWizardResult> ShowAsync(XamlRoot xamlRoot, ArcaneAlertRecord? alert)
    {
        PolicyWizardResult result = new PolicyWizardResult();
        List<PolicyWizardFieldChoice> choices = BuildChoices(alert);

        ComboBox typeBox = PolicyTypeBox(DefaultScope(alert));
        ComboBox actionBox = new ComboBox { Header = "Action", MinWidth = 220 };
        TextBox idBox = new TextBox { Header = "Id / key", Text = DefaultId(alert, ComboValue(typeBox, "Remote endpoint")) };
        TextBox scoreBox = new TextBox { Header = "Score", PlaceholderText = "90", MinWidth = 118, MaxWidth = 136, MaxLength = 3, VerticalAlignment = VerticalAlignment.Top };
        TextBox deltaBox = new TextBox { Header = "Delta", PlaceholderText = "10", MinWidth = 118, MaxWidth = 136, MaxLength = 3, VerticalAlignment = VerticalAlignment.Top };
        TextBox ownerBox = new TextBox { Header = "Owner", Text = "local-operator" };
        TextBox tagBox = new TextBox { Header = "Tag", PlaceholderText = "maintenance" };
        CalendarDatePicker expiresDatePicker = new CalendarDatePicker
        {
            Header = "Expires UTC",
            MinWidth = 240,
            PlaceholderText = "No expiration"
        };
        TimePicker expiresTimePicker = new TimePicker
        {
            Header = "Time",
            ClockIdentifier = "24HourClock",
            Width = 132,
            Time = TimeSpan.Zero,
            IsEnabled = false
        };
        Button clearExpiresButton = new Button
        {
            Width = 44,
            VerticalAlignment = VerticalAlignment.Bottom,
            Content = new FontIcon { FontSize = 14, Glyph = "\uE711" },
            IsEnabled = false
        };
        ToolTipService.SetToolTip(typeBox, PolicyScopeCatalog.ScopeHelpText(ComboValue(typeBox, "Remote endpoint")));
        ToolTipService.SetToolTip(actionBox, "What Arcane should do when this policy matches. Available actions depend on policy type.");
        ToolTipService.SetToolTip(idBox, "Stable identifier for this policy entry. Keep it short, descriptive, and unique.");
        ToolTipService.SetToolTip(scoreBox, "Optional 0-100 score. Only used by actions that set scored alert context.");
        ToolTipService.SetToolTip(deltaBox, "Optional amount to raise or lower an existing alert score. Only used by raise/lower actions.");
        ToolTipService.SetToolTip(ownerBox, "Optional owner or reviewer for alert tuning entries.");
        ToolTipService.SetToolTip(tagBox, "Optional tag added to policy context when this alert tuning entry applies.");
        ToolTipService.SetToolTip(clearExpiresButton, "Clear expiration so this policy does not expire.");
        ComboBox settingKeyBox = new ComboBox { Header = "Policy list", MinWidth = 260 };
        TextBox settingMapKeyBox = new TextBox { Header = "Map key" };
        TextBox settingValuesBox = new TextBox
        {
            Header = "Values",
            AcceptsReturn = true,
            MinHeight = 112,
            TextWrapping = TextWrapping.NoWrap
        };
        TextBox valueJsonBox = new TextBox { Text = "[]", Visibility = Visibility.Collapsed };
        TextBox reasonBox = new TextBox
        {
            Header = "Reason",
            AcceptsReturn = true,
            MinHeight = 72,
            TextWrapping = TextWrapping.Wrap,
            Text = DefaultReason(alert)
        };
        TextBox previewBox = new TextBox
        {
            Header = "Preview",
            AcceptsReturn = true,
            FontFamily = new Microsoft.UI.Xaml.Media.FontFamily("Consolas"),
            IsReadOnly = true,
            MinHeight = 180,
            TextWrapping = TextWrapping.NoWrap
        };
        TextBlock hintText = new TextBlock
        {
            Foreground = (Microsoft.UI.Xaml.Media.Brush)Application.Current.Resources["TextFillColorSecondaryBrush"],
            TextWrapping = TextWrapping.Wrap
        };
        TextBlock statusText = new TextBlock
        {
            Foreground = (Microsoft.UI.Xaml.Media.Brush)Application.Current.Resources["TextFillColorSecondaryBrush"],
            TextWrapping = TextWrapping.Wrap,
            MinHeight = 24
        };
        TextBlock settingHintText = new TextBlock
        {
            Foreground = (Microsoft.UI.Xaml.Media.Brush)Application.Current.Resources["TextFillColorSecondaryBrush"],
            TextWrapping = TextWrapping.Wrap
        };
        StackPanel choicePanel = new StackPanel { Spacing = 6 };
        StackPanel rulePanel = new StackPanel { Spacing = 8 };
        StackPanel settingPanel = new StackPanel { Spacing = 8 };

        foreach (PolicyWizardFieldChoice choice in choices)
        {
            Grid row = new Grid { ColumnSpacing = 8 };
            row.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(230) });
            row.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });

            CheckBox check = new CheckBox
            {
                Content = choice.Label,
                VerticalAlignment = VerticalAlignment.Center
            };
            FrameworkElement valueControl;
            if (choice.Options.Count > 0)
            {
                ComboBox combo = new ComboBox
                {
                    PlaceholderText = choice.Label.ToLowerInvariant(),
                    HorizontalAlignment = HorizontalAlignment.Stretch
                };

                foreach (string option in choice.Options.OrderBy(option => option, StringComparer.OrdinalIgnoreCase))
                {
                    combo.Items.Add(new ComboBoxItem { Content = option });
                }

                SelectComboValueOrClear(combo, choice.InitialValue);
                choice.ValueComboBox = combo;
                valueControl = combo;
            }
            else
            {
                TextBox value = new TextBox
                {
                    Text = choice.InitialValue,
                    PlaceholderText = choice.Label.ToLowerInvariant()
                };
                choice.ValueBox = value;
                valueControl = value;
            }

            ToolTipService.SetToolTip(check, choice.Help);
            ToolTipService.SetToolTip(valueControl, choice.Help);
            Grid.SetColumn(valueControl, 1);

            choice.CheckBox = check;
            row.Tag = choice;
            row.Children.Add(check);
            row.Children.Add(valueControl);
            choicePanel.Children.Add(row);
        }

        Grid top = new Grid { ColumnSpacing = 12 };
        top.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
        top.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
        Grid.SetColumn(actionBox, 1);
        top.Children.Add(typeBox);
        top.Children.Add(actionBox);

        Grid scoreGrid = new Grid { ColumnSpacing = 12 };
        scoreGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
        scoreGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
        scoreGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
        Grid.SetColumn(deltaBox, 1);
        Grid.SetColumn(hintText, 2);
        scoreGrid.Children.Add(scoreBox);
        scoreGrid.Children.Add(deltaBox);
        scoreGrid.Children.Add(hintText);

        StackPanel policyMetadataPanel = new StackPanel { Spacing = 12 };
        Grid ownerGrid = new Grid { ColumnSpacing = 12 };
        ownerGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
        ownerGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
        Grid.SetColumn(tagBox, 1);
        ownerGrid.Children.Add(ownerBox);
        ownerGrid.Children.Add(tagBox);

        Grid expirationGrid = new Grid { ColumnSpacing = 12 };
        expirationGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(260) });
        expirationGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(140) });
        expirationGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
        expirationGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
        TextBlock expirationHint = new TextBlock
        {
            Text = "Leave blank for no expiration.",
            VerticalAlignment = VerticalAlignment.Bottom,
            TextWrapping = TextWrapping.Wrap,
            Foreground = (Microsoft.UI.Xaml.Media.Brush)Application.Current.Resources["TextFillColorSecondaryBrush"]
        };
        Grid.SetColumn(expiresTimePicker, 1);
        Grid.SetColumn(clearExpiresButton, 2);
        Grid.SetColumn(expirationHint, 3);
        expirationGrid.Children.Add(expiresDatePicker);
        expirationGrid.Children.Add(expiresTimePicker);
        expirationGrid.Children.Add(clearExpiresButton);
        expirationGrid.Children.Add(expirationHint);

        policyMetadataPanel.Children.Add(ownerGrid);
        policyMetadataPanel.Children.Add(expirationGrid);

        rulePanel.Children.Add(new TextBlock
        {
            Text = alert == null ? "Choose one or more match fields, then enter the value to match." : "Choose one or more metadata fields from the alert. Edit values before saving if the match should be broader or narrower.",
            TextWrapping = TextWrapping.Wrap,
            Foreground = (Microsoft.UI.Xaml.Media.Brush)Application.Current.Resources["TextFillColorSecondaryBrush"]
        });
        rulePanel.Children.Add(choicePanel);
        rulePanel.Children.Add(scoreGrid);
        rulePanel.Children.Add(policyMetadataPanel);
        rulePanel.Children.Add(reasonBox);

        settingPanel.Children.Add(new TextBlock
        {
            Text = "Choose the policy list, then add values. The wizard generates policy JSON behind the scenes and merges new values with existing entries when possible.",
            TextWrapping = TextWrapping.Wrap,
            Foreground = (Microsoft.UI.Xaml.Media.Brush)Application.Current.Resources["TextFillColorSecondaryBrush"]
        });
        settingPanel.Children.Add(settingKeyBox);
        settingPanel.Children.Add(settingMapKeyBox);
        settingPanel.Children.Add(settingValuesBox);
        settingPanel.Children.Add(settingHintText);

        StackPanel body = new StackPanel
        {
            Spacing = 12,
            MaxWidth = 640,
            Margin = new Thickness(0, 0, 30, 0)
        };
        body.Children.Add(new TextBlock
        {
            Text = alert == null
                ? "Create a new policy entry. Nothing is saved until you press Save policy."
                : "Create a policy draft from the selected alert. Nothing is saved until you press Save policy.",
            TextWrapping = TextWrapping.Wrap
        });
        body.Children.Add(top);
        body.Children.Add(idBox);
        body.Children.Add(statusText);
        body.Children.Add(rulePanel);
        body.Children.Add(settingPanel);
        body.Children.Add(previewBox);

        ScrollViewer scroll = new ScrollViewer
        {
            Content = body,
            MaxHeight = 720,
            VerticalScrollBarVisibility = ScrollBarVisibility.Auto
        };

        void updateActions(bool resetAction)
        {
            string scope = ComboValue(typeBox, "Remote endpoint");
            string previousAction = ComboValue(actionBox, "");
            actionBox.Items.Clear();
            foreach (string action in ArcanePolicyStore.ActionsForScope(scope))
            {
                ComboBoxItem item = new ComboBoxItem { Content = action };
                ToolTipService.SetToolTip(item, PolicyScopeCatalog.ActionHelpText(scope, action));
                actionBox.Items.Add(item);
            }

            string desired = resetAction ? DefaultAction(alert, scope) : previousAction;
            SelectComboValue(actionBox, desired, ArcanePolicyStore.DefaultActionForScope(scope));
        }

        void updateSettingChoices(bool resetChoice)
        {
            string scope = ComboValue(typeBox, "Remote endpoint");
            string previous = ComboValue(settingKeyBox, "");
            List<PolicySettingChoice> settingChoices = PolicyScopeCatalog.SettingChoicesForScope(scope)
                .OrderBy(choice => choice.Label, StringComparer.OrdinalIgnoreCase)
                .ToList();

            settingKeyBox.Items.Clear();
            foreach (PolicySettingChoice choice in settingChoices)
            {
                ComboBoxItem item = new ComboBoxItem { Content = choice.Label, Tag = choice.Key };
                ToolTipService.SetToolTip(item, choice.Help);
                settingKeyBox.Items.Add(item);
            }

            string desired = resetChoice ? PolicyScopeCatalog.DefaultSettingKeyForScope(scope, alert) : previous;
            string fallback = settingChoices.Count == 0 ? "" : settingChoices[0].Key;
            SelectComboValue(settingKeyBox, desired, fallback);
        }

        void updateSettingFields(bool resetDefaults)
        {
            string scope = ComboValue(typeBox, "Remote endpoint");
            PolicySettingChoice choice = PolicyScopeCatalog.SelectedSettingChoice(scope, ComboValue(settingKeyBox, ""));
            bool isMap = choice.ValueKind.Equals("map-list", StringComparison.OrdinalIgnoreCase);
            settingMapKeyBox.Visibility = isMap ? Visibility.Visible : Visibility.Collapsed;
            settingMapKeyBox.Header = choice.MapKeyHeader;
            settingMapKeyBox.PlaceholderText = choice.MapKeyPlaceholder;
            settingValuesBox.Header = choice.ValuesHeader;
            settingValuesBox.PlaceholderText = choice.ValuesPlaceholder;
            settingHintText.Text = choice.Help;
            ToolTipService.SetToolTip(settingKeyBox, choice.Help);
            ToolTipService.SetToolTip(settingMapKeyBox, choice.Help);
            ToolTipService.SetToolTip(settingValuesBox, choice.Help);

            if (resetDefaults)
            {
                settingMapKeyBox.Text = PolicyScopeCatalog.DefaultSettingMapKey(choice, alert);
                settingValuesBox.Text = String.Join(Environment.NewLine, PolicyScopeCatalog.DefaultSettingValues(choice, alert));
            }

            idBox.Text = choice.Key;
            valueJsonBox.Text = BuildSettingValueJson(choice, settingMapKeyBox.Text, settingValuesBox.Text);
        }

        void updateVisibility(bool resetDefaults)
        {
            string scope = ComboValue(typeBox, "Remote endpoint");
            string action = ComboValue(actionBox, ArcanePolicyStore.DefaultActionForScope(scope));
            bool isRule = ArcanePolicyStore.IsRuleScope(scope);
            bool isDetection = scope.Equals("Detection", StringComparison.OrdinalIgnoreCase);
            bool scoreRelevant = PolicyScopeCatalog.IsScoreRelevant(scope, action);
            bool deltaRelevant = PolicyScopeCatalog.IsDeltaRelevant(scope, action);
            ToolTipService.SetToolTip(typeBox, PolicyScopeCatalog.ScopeHelpText(scope));
            ToolTipService.SetToolTip(actionBox, PolicyScopeCatalog.ActionHelpText(scope, action));
            ToolTipService.SetToolTip(scoreBox, PolicyScopeCatalog.ScoreToolTipText(scope, action));
            ToolTipService.SetToolTip(deltaBox, PolicyScopeCatalog.DeltaToolTipText(scope, action));
            ToolTipService.SetToolTip(expiresDatePicker, "Optional UTC expiration date for temporary alert tuning. Leave blank for no expiration.");
            ToolTipService.SetToolTip(expiresTimePicker, "UTC time for the selected expiration date.");
            idBox.Visibility = isRule ? Visibility.Visible : Visibility.Collapsed;
            rulePanel.Visibility = isRule ? Visibility.Visible : Visibility.Collapsed;
            settingPanel.Visibility = isRule ? Visibility.Collapsed : Visibility.Visible;
            policyMetadataPanel.Visibility = isDetection ? Visibility.Visible : Visibility.Collapsed;
            expiresTimePicker.IsEnabled = isDetection && expiresDatePicker.Date.HasValue;
            clearExpiresButton.IsEnabled = isDetection && expiresDatePicker.Date.HasValue;
            scoreBox.IsEnabled = scoreRelevant;
            deltaBox.IsEnabled = deltaRelevant;
            scoreBox.PlaceholderText = scoreRelevant ? "0-100" : "-";
            deltaBox.PlaceholderText = deltaRelevant ? "+/-" : "-";
            hintText.Text = PolicyScopeCatalog.ScoreHintText(scope, action);
            valueJsonBox.Text = isRule ? "[]" : PolicyScopeCatalog.DefaultValueJsonForScope(scope);

            foreach (Grid row in choicePanel.Children.OfType<Grid>())
            {
                PolicyWizardFieldChoice choice = (PolicyWizardFieldChoice)row.Tag;
                bool applies = choice.AppliesTo(scope);
                bool hasAlertValue = !String.IsNullOrWhiteSpace(choice.InitialValue);
                row.Visibility = applies && (alert == null || hasAlertValue) ? Visibility.Visible : Visibility.Collapsed;
                if (resetDefaults && choice.CheckBox != null)
                {
                    choice.CheckBox.IsChecked = applies && choice.DefaultForScope(scope);
                }
            }

            if (resetDefaults)
            {
                idBox.Text = DefaultId(alert, scope);
                scoreBox.Text = scoreRelevant ? PolicyScopeCatalog.DefaultScoreForAction(scope, action) : "";
                deltaBox.Text = deltaRelevant ? PolicyScopeCatalog.DefaultDeltaForAction(scope, action) : "";
            }
            else
            {
                if (!scoreRelevant)
                {
                    scoreBox.Text = "";
                }

                if (!deltaRelevant)
                {
                    deltaBox.Text = "";
                }
            }

            if (!isRule)
            {
                updateSettingFields(resetDefaults);
            }
        }

        ContentDialog? dialog = null;

        void updatePreview()
        {
            string scope = ComboValue(typeBox, "Remote endpoint");
            bool isRule = ArcanePolicyStore.IsRuleScope(scope);
            string readiness = SaveReadinessMessage(scope, valueJsonBox.Text, choices);
            bool canSave = String.IsNullOrWhiteSpace(readiness);
            if (dialog != null)
            {
                dialog.IsPrimaryButtonEnabled = canSave;
            }

            try
            {
                previewBox.Text = isRule
                    ? BuildRulePreview(scope, ComboValue(actionBox, ArcanePolicyStore.DefaultActionForScope(scope)), idBox.Text, reasonBox.Text, scoreBox.Text, deltaBox.Text, ownerBox.Text, tagBox.Text, FormatExpirationUtc(expiresDatePicker, expiresTimePicker), choices)
                    : BuildSettingPreview(scope, idBox.Text, valueJsonBox.Text);
                statusText.Text = canSave
                    ? "Ready to save. A backup and validation run will happen automatically."
                    : readiness;
            }
            catch (Exception ex)
            {
                previewBox.Text = "";
                statusText.Text = FirstNonEmpty(readiness, ex.Message);
                if (dialog != null)
                {
                    dialog.IsPrimaryButtonEnabled = false;
                }
            }
        }

        void refresh(bool resetDefaults)
        {
            updateActions(resetDefaults);
            updateSettingChoices(resetDefaults);
            updateVisibility(resetDefaults);
            updatePreview();
        }

        typeBox.SelectionChanged += (_, _) => refresh(true);
        actionBox.SelectionChanged += (_, _) =>
        {
            updateVisibility(false);
            updatePreview();
        };
        settingKeyBox.SelectionChanged += (_, _) =>
        {
            updateSettingFields(true);
            updatePreview();
        };
        idBox.TextChanged += (_, _) => updatePreview();
        scoreBox.TextChanged += (_, _) => updatePreview();
        deltaBox.TextChanged += (_, _) => updatePreview();
        ownerBox.TextChanged += (_, _) => updatePreview();
        tagBox.TextChanged += (_, _) => updatePreview();
        expiresDatePicker.DateChanged += (_, _) =>
        {
            expiresTimePicker.IsEnabled = expiresDatePicker.Date.HasValue;
            clearExpiresButton.IsEnabled = expiresDatePicker.Date.HasValue;
            updatePreview();
        };
        expiresTimePicker.TimeChanged += (_, _) => updatePreview();
        clearExpiresButton.Click += (_, _) =>
        {
            expiresDatePicker.Date = null;
            expiresTimePicker.Time = TimeSpan.Zero;
            expiresTimePicker.IsEnabled = false;
            clearExpiresButton.IsEnabled = false;
            updatePreview();
        };
        settingMapKeyBox.TextChanged += (_, _) =>
        {
            updateSettingFields(false);
            updatePreview();
        };
        settingValuesBox.TextChanged += (_, _) =>
        {
            updateSettingFields(false);
            updatePreview();
        };
        reasonBox.TextChanged += (_, _) => updatePreview();
        foreach (PolicyWizardFieldChoice choice in choices)
        {
            if (choice.CheckBox != null) choice.CheckBox.Checked += (_, _) => updatePreview();
            if (choice.CheckBox != null) choice.CheckBox.Unchecked += (_, _) => updatePreview();
            if (choice.ValueBox != null) choice.ValueBox.TextChanged += (_, _) => updatePreview();
            if (choice.ValueComboBox != null) choice.ValueComboBox.SelectionChanged += (_, _) => updatePreview();
        }

        refresh(true);

        dialog = new ContentDialog
        {
            XamlRoot = xamlRoot,
            Title = alert == null ? "New policy wizard" : "Create policy from alert",
            Content = scroll,
            PrimaryButtonText = "Save policy",
            CloseButtonText = "Cancel",
            DefaultButton = ContentDialogButton.Primary
        };
        updatePreview();

        dialog.PrimaryButtonClick += async (_, args) =>
        {
            ContentDialogButtonClickDeferral deferral = args.GetDeferral();
            try
            {
                string scope = ComboValue(typeBox, "Remote endpoint");
                ArcanePolicyEditRequest request = BuildRequest(
                    scope,
                    ComboValue(actionBox, ArcanePolicyStore.DefaultActionForScope(scope)),
                    idBox.Text,
                    reasonBox.Text,
                    scoreBox.Text,
                    deltaBox.Text,
                    ownerBox.Text,
                    tagBox.Text,
                    FormatExpirationUtc(expiresDatePicker, expiresTimePicker),
                    valueJsonBox.Text,
                    choices);

                string saveResult = ArcanePolicyStore.SaveEdit(request);
                ArcaneValidationReport validation = await ArcaneValidationView.RunAsync();
                result.Saved = validation.ErrorCount == 0;
                result.Scope = scope;
                result.Id = request.Id;
                result.Status = saveResult + Environment.NewLine +
                    ArcaneValidationView.Heading(validation) + Environment.NewLine +
                    ArcaneValidationView.BuildOverviewText(validation);

                if (validation.ErrorCount > 0)
                {
                    args.Cancel = true;
                    statusText.Text = result.Status;
                    result.Saved = false;
                }
            }
            catch (Exception ex)
            {
                args.Cancel = true;
                statusText.Text = "Policy was not saved: " + ex.Message;
                dialog.IsPrimaryButtonEnabled = false;
            }
            finally
            {
                deferral.Complete();
            }
        };

        await dialog.ShowAsync();
        return result;
    }

    private static string SaveReadinessMessage(
        string scope,
        string valueJson,
        IReadOnlyList<PolicyWizardFieldChoice> choices)
    {
        if (ArcanePolicyStore.IsRuleScope(scope))
        {
            bool hasAnyApplicableValue = false;
            foreach (PolicyWizardFieldChoice choice in choices)
            {
                if (!choice.AppliesTo(scope)) continue;
                if (!String.IsNullOrWhiteSpace(choice.Value())) hasAnyApplicableValue = true;
                if (choice.CheckBox?.IsChecked == true)
                {
                    return String.IsNullOrWhiteSpace(choice.Value())
                        ? choice.Label + " is selected but has no value."
                        : "";
                }
            }

            return hasAnyApplicableValue
                ? "Choose at least one match field below before saving. For alert tuning, start narrow: Rule ID plus Process name is usually a good first draft."
                : "Enter at least one match value before saving.";
        }

        string trimmed = valueJson.Trim();
        if (String.IsNullOrWhiteSpace(trimmed) ||
            trimmed.Equals("[]", StringComparison.Ordinal) ||
            trimmed.Equals("{}", StringComparison.Ordinal))
        {
            return "Enter at least one value for this policy list before saving.";
        }

        return "";
    }

    private static ComboBox PolicyTypeBox(string selectedScope)
    {
        ComboBox combo = new ComboBox { Header = "Policy type", MinWidth = 210 };
        foreach (PolicyScopeDefinition definition in PolicyScopeCatalog.AllAlphabetical())
        {
            ComboBoxItem item = new ComboBoxItem { Content = definition.DisplayName, Tag = definition.Scope };
            ToolTipService.SetToolTip(item, PolicyScopeCatalog.ScopeHelpText(definition.Scope));
            combo.Items.Add(item);
        }

        SelectComboValue(combo, selectedScope, "Remote endpoint");
        ToolTipService.SetToolTip(combo, PolicyScopeCatalog.ScopeHelpText(ComboValue(combo, selectedScope)));
        return combo;
    }

    private static ArcanePolicyEditRequest BuildRequest(
        string scope,
        string action,
        string id,
        string reason,
        string score,
        string delta,
        string owner,
        string tag,
        string expires,
        string valueJson,
        IReadOnlyList<PolicyWizardFieldChoice> choices)
    {
        bool isRule = ArcanePolicyStore.IsRuleScope(scope);
        return new ArcanePolicyEditRequest
        {
            Scope = scope,
            SectionName = ArcanePolicyStore.SectionNameForScope(scope),
            IsRule = isRule,
            IsNew = true,
            Id = FirstNonEmpty(id.Trim(), DefaultId(null, scope)),
            Enabled = true,
            Action = action,
            Score = PolicyScopeCatalog.IsScoreRelevant(scope, action) ? score.Trim() : "",
            ScoreDelta = PolicyScopeCatalog.IsDeltaRelevant(scope, action) ? delta.Trim() : "",
            Owner = owner.Trim(),
            Tag = tag.Trim(),
            ExpiresUtc = expires.Trim(),
            Reason = reason.Trim(),
            MatchJson = isRule ? BuildMatchJson(scope, choices) : "{}",
            ValueJson = isRule ? "[]" : valueJson.Trim()
        };
    }

    private static string BuildRulePreview(
        string scope,
        string action,
        string id,
        string reason,
        string score,
        string delta,
        string owner,
        string tag,
        string expires,
        IReadOnlyList<PolicyWizardFieldChoice> choices)
    {
        Dictionary<string, object> rule = new Dictionary<string, object>(StringComparer.OrdinalIgnoreCase)
        {
            ["id"] = FirstNonEmpty(id.Trim(), DefaultId(null, scope)),
            ["enabled"] = true,
            ["action"] = action,
            ["reason"] = reason,
            ["match"] = JsonSerializer.Deserialize<Dictionary<string, string>>(BuildMatchJson(scope, choices)) ?? new Dictionary<string, string>()
        };

        if (PolicyScopeCatalog.IsScoreRelevant(scope, action) &&
            Int32.TryParse(score.Trim(), NumberStyles.Integer, CultureInfo.InvariantCulture, out int parsedScore))
        {
            rule["score"] = parsedScore;
        }

        if (scope.Equals("Detection", StringComparison.OrdinalIgnoreCase))
        {
            if (PolicyScopeCatalog.IsDeltaRelevant(scope, action) &&
                Int32.TryParse(delta.Trim(), NumberStyles.Integer, CultureInfo.InvariantCulture, out int parsedDelta))
            {
                rule["score_delta"] = parsedDelta;
            }

            if (!String.IsNullOrWhiteSpace(owner)) rule["owner"] = owner.Trim();
            if (!String.IsNullOrWhiteSpace(tag)) rule["tag"] = tag.Trim();
            if (!String.IsNullOrWhiteSpace(expires)) rule["expires_utc"] = expires.Trim();
        }

        return GuiJson.SerializeIndented(rule);
    }

    private static string BuildSettingPreview(string scope, string id, string valueJson)
    {
        object? parsed = JsonSerializer.Deserialize<object>(String.IsNullOrWhiteSpace(valueJson) ? "[]" : valueJson);
        Dictionary<string, object?> preview = new Dictionary<string, object?>
        {
            ["scope"] = scope,
            ["key"] = FirstNonEmpty(id.Trim(), DefaultId(null, scope)),
            ["value"] = parsed
        };
        return GuiJson.SerializeIndented(preview);
    }

    private static string BuildMatchJson(string scope, IReadOnlyList<PolicyWizardFieldChoice> choices)
    {
        Dictionary<string, string> match = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (PolicyWizardFieldChoice choice in choices)
        {
            if (choice.CheckBox?.IsChecked != true || !choice.AppliesTo(scope)) continue;
            string field = choice.FieldForScope(scope);
            string value = choice.Value();
            if (String.IsNullOrWhiteSpace(value))
            {
                throw new InvalidOperationException(choice.Label + " is checked but has no value.");
            }

            match[field] = value;
        }

        if (match.Count == 0)
        {
            throw new InvalidOperationException("Choose at least one match field before saving this rule.");
        }

        return GuiJson.SerializeIndented(match);
    }

    private static List<PolicyWizardFieldChoice> BuildChoices(ArcaneAlertRecord? alert)
    {
        List<PolicyWizardFieldChoice> choices = new List<PolicyWizardFieldChoice>();
        foreach (PolicyMatchFieldDefinition definition in PolicyScopeCatalog.MatchFieldDefinitions.OrderBy(definition => definition.Label, StringComparer.OrdinalIgnoreCase))
        {
            string initialValue = InitialValueForSource(alert, definition.InitialValueSource);
            AddChoice(
                choices,
                definition,
                initialValue,
                OptionsWithInitial(initialValue, PolicyScopeCatalog.OptionsForSource(definition.OptionsSource)));
        }

        return choices;
    }

    private static void AddChoice(
        List<PolicyWizardFieldChoice> choices,
        PolicyMatchFieldDefinition definition,
        string? value,
        IReadOnlyList<string>? options = null)
    {
        choices.Add(new PolicyWizardFieldChoice
        {
            Label = definition.Label,
            NetworkField = definition.NetworkField,
            DetectionField = definition.DetectionField,
            InitialValue = value ?? "",
            Options = options ?? Array.Empty<string>(),
            DefaultNetwork = definition.DefaultNetwork,
            DefaultDetection = definition.DefaultDetection,
            Help = definition.Help
        });
    }

    private static string InitialValueForSource(ArcaneAlertRecord? alert, string source)
    {
        if (alert == null || String.IsNullOrWhiteSpace(source))
        {
            return "";
        }

        if (source.StartsWith("metadata:", StringComparison.OrdinalIgnoreCase))
        {
            return alert.MetadataValue(source.Substring("metadata:".Length));
        }

        return source switch
        {
            "category" => alert.Category,
            "company" => alert.Company,
            "country" => alert.Country,
            "domain" => FirstNonEmpty(alert.MetadataValue("registrable_domain"), alert.MetadataValue("resolved_domain"), alert.MetadataValue("sni_hostname"), alert.MetadataValue("rdns")),
            "process" => alert.Process,
            "remote_ip" => alert.RemoteIp,
            "rule_id" => alert.RuleId,
            "title" => alert.Title,
            _ => ""
        };
    }

    private static IReadOnlyList<string> OptionsWithInitial(string? initial, IReadOnlyList<string> options)
    {
        List<string> values = new List<string>();
        if (!String.IsNullOrWhiteSpace(initial))
        {
            values.Add(initial.Trim());
        }

        foreach (string option in options)
        {
            if (!values.Any(value => value.Equals(option, StringComparison.OrdinalIgnoreCase)))
            {
                values.Add(option);
            }
        }

        return values;
    }

    private static string BuildSettingValueJson(PolicySettingChoice choice, string mapKey, string valuesText)
    {
        List<string> values = SplitLines(valuesText);
        if (choice.ValueKind.Equals("map-list", StringComparison.OrdinalIgnoreCase))
        {
            if (String.IsNullOrWhiteSpace(mapKey))
            {
                return "{}";
            }

            if (values.Count == 0)
            {
                return "{}";
            }

            Dictionary<string, IReadOnlyList<string>> map = new Dictionary<string, IReadOnlyList<string>>(StringComparer.OrdinalIgnoreCase)
            {
                [mapKey.Trim()] = values
            };
            return GuiJson.SerializeIndented(map);
        }

        if (values.Count == 0)
        {
            return "[]";
        }

        return GuiJson.SerializeIndented(values);
    }

    private static List<string> SplitLines(string text)
    {
        return (text ?? "")
            .Split(new[] { "\r\n", "\n", "\r" }, StringSplitOptions.None)
            .Select(line => line.Trim())
            .Where(line => !String.IsNullOrWhiteSpace(line))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();
    }

    private static string FormatExpirationUtc(CalendarDatePicker datePicker, TimePicker timePicker)
    {
        DateTimeOffset? date = datePicker.Date;
        if (!date.HasValue)
        {
            return "";
        }

        DateTimeOffset utc = new DateTimeOffset(
            date.Value.Year,
            date.Value.Month,
            date.Value.Day,
            timePicker.Time.Hours,
            timePicker.Time.Minutes,
            0,
            TimeSpan.Zero);
        return utc.ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", CultureInfo.InvariantCulture);
    }

    private static string DefaultScope(ArcaneAlertRecord? alert)
    {
        if (alert != null &&
            (alert.Category.Equals("Network", StringComparison.OrdinalIgnoreCase) ||
             !String.IsNullOrWhiteSpace(alert.RemoteIp) ||
             !String.IsNullOrWhiteSpace(alert.Company)))
        {
            return "Remote endpoint";
        }

        return "Detection";
    }

    private static string DefaultAction(ArcaneAlertRecord? alert, string scope)
    {
        if (scope.Equals("Remote endpoint", StringComparison.OrdinalIgnoreCase))
        {
            return alert == null ? "observe" : "trust";
        }

        if (scope.Equals("Detection", StringComparison.OrdinalIgnoreCase))
        {
            return "suppress_external";
        }

        return ArcanePolicyStore.DefaultActionForScope(scope);
    }

    private static string DefaultId(ArcaneAlertRecord? alert, string scope)
    {
        string stamp = DateTime.Now.ToString("yyyyMMdd-HHmmss", CultureInfo.InvariantCulture);
        string source = alert == null ? "" : SafeToken(FirstNonEmpty(alert.Process, alert.RuleId, alert.Category));
        if (!String.IsNullOrWhiteSpace(source)) source += "-";

        if (scope.Equals("Detection", StringComparison.OrdinalIgnoreCase)) return "local-alert-" + source + stamp;
        if (scope.Equals("Allowlist", StringComparison.OrdinalIgnoreCase)) return "new_allowlist";
        if (scope.Equals("Blocklist", StringComparison.OrdinalIgnoreCase)) return "new_blocklist";
        if (scope.Equals("Response", StringComparison.OrdinalIgnoreCase)) return "new_response_guardrail";
        return "local-endpoint-" + source + stamp;
    }

    private static string DefaultReason(ArcaneAlertRecord? alert)
    {
        if (alert == null)
        {
            return "Created from the GUI policy wizard. Review match fields and keep this entry as narrow as practical.";
        }

        return "Created from alert " + alert.RuleId + " at " + alert.SystemTimeDisplay + ". Review match fields and keep this entry as narrow as practical.";
    }

    private static void SelectComboValue(ComboBox combo, string desired, string fallback)
    {
        string target = FirstNonEmpty(desired, fallback);
        for (int index = 0; index < combo.Items.Count; index++)
        {
            if (combo.Items[index] is ComboBoxItem item &&
                target.Equals(ComboItemValue(item), StringComparison.OrdinalIgnoreCase))
            {
                combo.SelectedIndex = index;
                return;
            }
        }

        combo.SelectedIndex = combo.Items.Count > 0 ? 0 : -1;
    }

    private static void SelectComboValueOrClear(ComboBox combo, string desired)
    {
        if (String.IsNullOrWhiteSpace(desired))
        {
            combo.SelectedIndex = -1;
            return;
        }

        for (int index = 0; index < combo.Items.Count; index++)
        {
            if (combo.Items[index] is ComboBoxItem item &&
                desired.Equals(ComboItemValue(item), StringComparison.OrdinalIgnoreCase))
            {
                combo.SelectedIndex = index;
                return;
            }
        }

        combo.SelectedIndex = -1;
    }

    private static string ComboValue(ComboBox combo, string fallback)
    {
        return combo.SelectedItem is ComboBoxItem item ? ComboItemValue(item) : fallback;
    }

    private static string ComboItemValue(ComboBoxItem item)
    {
        string? tag = item.Tag?.ToString();
        return String.IsNullOrWhiteSpace(tag) ? item.Content?.ToString() ?? "" : tag;
    }

    private static string SafeToken(string value)
    {
        string text = value.ToLowerInvariant();
        char[] chars = text.Select(ch => Char.IsLetterOrDigit(ch) ? ch : '-').ToArray();
        string token = new string(chars).Trim('-');
        while (token.Contains("--", StringComparison.Ordinal))
        {
            token = token.Replace("--", "-", StringComparison.Ordinal);
        }

        return token.Length > 32 ? token.Substring(0, 32).Trim('-') : token;
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
