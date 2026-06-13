$ErrorActionPreference = "Stop"

$root = Split-Path -Parent $PSScriptRoot

function Fail-Test {
    param([string]$Message)
    throw $Message
}

function Assert-Contains {
    param(
        [string]$Text,
        [string]$Needle,
        [string]$Name
    )

    if ($Text.IndexOf($Needle, [System.StringComparison]::OrdinalIgnoreCase) -lt 0) {
        Fail-Test "$Name should contain '$Needle'."
    }
}

function Assert-NotContains {
    param(
        [string]$Text,
        [string]$Needle,
        [string]$Name
    )

    if ($Text.IndexOf($Needle, [System.StringComparison]::OrdinalIgnoreCase) -ge 0) {
        Fail-Test "$Name should not contain '$Needle'."
    }
}

$xaml = Get-Content -LiteralPath (Join-Path $root "src\ArcaneEDR.Gui\Pages\PolicyPage.xaml") -Raw
$code = Get-Content -LiteralPath (Join-Path $root "src\ArcaneEDR.Gui\Pages\PolicyPage.xaml.cs") -Raw
$store = Get-Content -LiteralPath (Join-Path $root "src\ArcaneEDR.Gui\Services\ArcanePolicyStore.cs") -Raw
$wizard = Get-Content -LiteralPath (Join-Path $root "src\ArcaneEDR.Gui\Services\PolicyWizard.cs") -Raw
$scopeCatalog = Get-Content -LiteralPath (Join-Path $root "src\ArcaneEDR.Gui\Services\PolicyScopeCatalog.cs") -Raw
$guiJson = Get-Content -LiteralPath (Join-Path $root "src\ArcaneEDR.Gui\Services\GuiJson.cs") -Raw
$configXaml = Get-Content -LiteralPath (Join-Path $root "src\ArcaneEDR.Gui\Pages\ConfigurationPage.xaml") -Raw
$configStore = Get-Content -LiteralPath (Join-Path $root "src\ArcaneEDR.Gui\Services\ArcaneConfigFile.cs") -Raw

Assert-Contains $xaml 'TabView x:Name="PolicyTabs"' "Policy page tabs"
Assert-Contains $xaml 'Header="Entries"' "Policy entries tab"
Assert-Contains $xaml 'x:Name="PolicyEntriesList"' "Policy entries list"
Assert-Contains $xaml 'x:Name="PolicyScopeFilterBox"' "Policy scope filter"
Assert-Contains $xaml 'x:Name="PolicySearchBox"' "Policy search"
Assert-Contains $xaml 'x:Name="AddPolicyButton"' "Unified add policy command"
Assert-Contains $xaml 'x:Name="PolicyHideDisabledBox"' "Policy hide disabled filter"
Assert-Contains $xaml 'IsChecked="True"' "Policy hide disabled default checked"
Assert-Contains $xaml 'AddPolicy_Click' "Guided add policy wizard"
Assert-Contains $xaml 'x:Name="SortOrderButton"' "Policy order sort header"
Assert-Contains $xaml 'x:Name="SortTypeButton"' "Policy type sort header"
Assert-Contains $xaml 'x:Name="SortPolicyButton"' "Policy id sort header"
Assert-Contains $xaml 'x:Name="SortEnabledButton"' "Policy enabled sort header"
Assert-Contains $xaml 'x:Name="SortActionButton"' "Policy action sort header"
Assert-Contains $xaml 'x:Name="SortSummaryButton"' "Policy summary sort header"
Assert-Contains $xaml 'SavePolicyEntry_Click' "Save policy command"
Assert-Contains $xaml 'DeletePolicyEntry_Click' "Delete policy command"
Assert-Contains $xaml 'MoveHigher_Click' "Move higher priority command"
Assert-Contains $xaml 'MoveLower_Click' "Move lower priority command"
Assert-Contains $xaml 'FormatMatch_Click' "Format match JSON command"
Assert-Contains $xaml 'x:Name="PolicyEditorScopeBox"' "Policy editor scope"
Assert-Contains $xaml 'x:Name="PolicyEditorPriorityText"' "Policy editor priority"
Assert-Contains $xaml 'x:Name="PolicyOrderHintText"' "Policy order hint"
Assert-Contains $xaml 'x:Name="PolicyEditorScrollContent"' "Policy editor scroll gutter"
Assert-Contains $xaml 'Margin="0,0,26,0"' "Policy editor right scroll gutter"
Assert-Contains $xaml 'x:Name="EditorMoveHigherButton"' "Editor move higher command"
Assert-Contains $xaml 'x:Name="EditorMoveLowerButton"' "Editor move lower command"
Assert-Contains $xaml '<ComboBox' "Static dropdown controls"
Assert-Contains $xaml 'x:Name="PolicyEditorActionBox"' "Policy editor action dropdown"
Assert-Contains $xaml 'PolicyEditorAction_Changed' "Policy action change handler"
Assert-Contains $xaml 'x:Name="PolicyScoreHintText"' "Policy score/delta hint"
Assert-Contains $xaml 'x:Name="DetectionMetadataPanel"' "Detection-only metadata panel"
Assert-Contains $xaml 'x:Name="PolicyEditorExpiresDatePicker"' "Policy expiration date picker"
Assert-Contains $xaml 'x:Name="PolicyEditorExpiresTimePicker"' "Policy expiration time picker"
Assert-Contains $xaml 'x:Name="PolicyEditorClearExpiresButton"' "Policy expiration clear command"
Assert-Contains $xaml 'PlaceholderText="No expiration"' "Policy expiration blank default"
Assert-Contains $xaml 'x:Name="PolicyEditorMatchJsonBox"' "Policy editor match JSON"
Assert-Contains $xaml 'x:Name="PolicyEditorSettingValueBox"' "Policy editor setting JSON"
Assert-Contains $xaml 'x:Name="SelectedPolicyDetailText"' "Selected policy detail"
Assert-Contains $xaml 'Header="Inspect Output"' "Policy inspect output tab"
Assert-Contains $xaml 'TextBlock x:Name="PolicyOutputText" Style="{StaticResource ConsoleTextStyle}"' "Policy output text"
Assert-Contains $xaml 'Header="Raw JSON"' "Policy raw JSON tab"
Assert-Contains $xaml 'x:Name="PolicyRawText"' "Policy raw JSON text"

Assert-Contains $code "ArcanePolicyStore.Load" "Policy store load"
Assert-Contains $code "ApplyPolicyFilters" "Policy filter handler"
Assert-Contains $code "ShowSelectedPolicyEntry" "Selected policy details"
Assert-Contains $code "BuildEditRequest" "Policy edit request builder"
Assert-Contains $code "ArcanePolicyStore.SaveEdit" "Policy save"
Assert-Contains $code "ArcanePolicyStore.DeleteEntry" "Policy delete"
Assert-Contains $code "ArcanePolicyStore.MoveEntry" "Policy order move"
Assert-Contains $code "PolicyWizard.ShowAsync" "Unified policy create wizard"
Assert-NotContains $code "FillNewPolicyDraft" "Obsolete inline new policy editor"
Assert-NotContains $code "StartNewPolicy" "Obsolete inline new policy entry point"
Assert-Contains $code "PopulateEditorScopes" "Policy editor scope catalog binding"
Assert-Contains $code "PolicyScopeCatalog.DisplayNameForScope" "Policy page scope display catalog"
Assert-Contains $code "PolicyScopeCatalog.ScopeHelpText" "Policy page type help text"
Assert-Contains $code "PolicyScopeCatalog.AllAlphabetical" "Policy page alphabetical type dropdown"
Assert-Contains $code "RefreshPolicyAfterMutationAsync" "Policy CRUD refresh"
Assert-Contains $code "SetActionCombo" "Policy action dropdown population"
Assert-Contains $code "UpdateActionDependentFields" "Policy action-dependent hints"
Assert-Contains $code "ActionHelpText" "Policy action help text"
Assert-Contains $code "PolicyScopeCatalog.ScoreHintText" "Policy score help text"
Assert-Contains $code "PolicyScopeCatalog.ActionHelpText" "Policy action help text"
Assert-Contains $code "SortPolicyEntries" "Policy table sorting"
Assert-Contains $code "UpdateSortIndicators" "Policy sort indicators"
Assert-Contains $code "PolicyHideDisabledBox.IsChecked" "Policy hide disabled filter"
Assert-Contains $code "RestorePolicyViewSettings" "Policy view settings restore"
Assert-Contains $code "SavePolicyViewSettings" "Policy view settings save"
Assert-Contains $code "settings.PolicyHideDisabled" "Policy hide disabled persisted setting"
Assert-Contains $code 'ChangePolicySort("enabled")' "Policy enabled sort"
Assert-Contains $code 'ChangePolicySort("action")' "Policy action sort"
Assert-Contains $code "PolicyEditorScopeBox.IsEnabled = false" "Policy scope locked to wizard-created entry type"
Assert-Contains $code "Select a saved policy entry to edit, or use Add policy to create one." "Save guard for no selection"
Assert-Contains $code "DetectionMetadataPanel.Visibility = isDetection" "Detection metadata visibility"
Assert-Contains $code "PolicyEditorEnabledSwitch.Visibility = isRule" "Rule-only enabled switch visibility"
Assert-Contains $code "SetEditorExpiration" "Policy expiration picker binding"
Assert-Contains $code "FormatEditorExpirationUtc" "Policy expiration ISO formatting"
Assert-Contains $code "ClearEditorExpiration_Click" "Policy expiration clear handler"
Assert-Contains $code "ArcaneValidationView.RunAsync" "Policy save validation"
Assert-Contains $code "--policy-inspect" "Policy inspect command"
Assert-Contains $code "GuiCommandStatus.RunAsync" "Policy command status"

Assert-Contains $store "remote_endpoint_policies" "Remote endpoint policy parsing"
Assert-Contains $store "detection_policies" "Detection policy parsing"
Assert-Contains $store "response_policy" "Response policy parsing"
Assert-Contains $store "allowlists" "Allowlist parsing"
Assert-Contains $store "blocklists" "Blocklist parsing"
Assert-Contains $store "ItemCount" "Policy item count"
Assert-Contains $store "PriorityDisplay" "Policy priority display"
Assert-Contains $store "TypeDisplay" "Friendly policy type display"
Assert-Contains $store "SaveEdit" "Policy structured save"
Assert-Contains $store "DeleteEntry" "Policy structured delete"
Assert-Contains $store "MoveEntry" "Policy structured order move"
Assert-Contains $store "ActionsForScope" "Policy action enumerations"
Assert-Contains $store "OriginalId" "Policy update original key tracking"
Assert-Contains $store "DefaultValueJsonForScope" "Policy create value defaults"
Assert-Contains $store "DefaultMatchJsonForScope" "Policy create defaults"
Assert-Contains $store "MergeSettingValue" "Policy setting wizard merge save"
Assert-Contains $store "JsonNodeEquivalent" "Policy setting merge de-duplication"
Assert-Contains $wizard "internal static class PolicyWizard" "Shared policy wizard"
Assert-Contains $wizard "Create policy from alert" "Alert-derived wizard mode"
Assert-Contains $wizard "New policy wizard" "Blank new policy wizard mode"
Assert-Contains $wizard "Margin = new Thickness(0, 0, 36, 0)" "Policy wizard right scroll gutter"
Assert-Contains $wizard "OptionsWithInitial" "Policy wizard enumerated match values"
Assert-Contains $wizard "KnownCategories" "Policy wizard category dropdown values"
Assert-NotContains $wizard "KnownRemotePorts" "Remote port remains free-form"
Assert-Contains $wizard "KnownCountryCodes" "Policy wizard country dropdown values"
Assert-Contains $wizard "ValueComboBox" "Policy wizard dropdown match control"
Assert-Contains $wizard "DefaultNetwork = false" "Policy wizard does not auto-check alert fields"
Assert-Contains $wizard '"path_prefix"' "Policy wizard process path prefix match"
Assert-Contains $wizard '"signer"' "Policy wizard signer match"
Assert-Contains $wizard "IsPrimaryButtonEnabled = canSave" "Policy wizard disables save until draft is ready"
Assert-Contains $wizard "SaveReadinessMessage" "Policy wizard save readiness validation"
Assert-Contains $wizard "Choose at least one match field below before saving" "Policy wizard visible no-match guidance"
Assert-Contains $wizard "Ready to save. A backup and validation run will happen automatically." "Policy wizard visible ready state"
Assert-Contains $wizard "PolicyScopeCatalog.AllAlphabetical" "Policy wizard alphabetical policy types"
Assert-Contains $wizard "PolicyScopeCatalog.ScopeHelpText" "Policy wizard policy type help"
Assert-Contains $wizard "PolicyScopeCatalog.ActionHelpText" "Policy wizard action help"
Assert-Contains $wizard "PolicySettingChoice" "Policy wizard friendly setting model"
Assert-Contains $wizard "Policy list" "Policy wizard setting key dropdown"
Assert-Contains $wizard "one value per line" "Policy wizard setting values input"
Assert-Contains $wizard "BuildSettingValueJson" "Policy wizard generated setting JSON"
Assert-Contains $wizard "process_allowed_outbound_ports" "Policy wizard map setting support"
Assert-Contains $wizard "Expires UTC" "Policy wizard expiration date picker"
Assert-Contains $wizard "UTC time" "Policy wizard expiration time picker"
Assert-Contains $wizard "No expiration" "Policy wizard optional expiration"
Assert-Contains $wizard "FormatExpirationUtc" "Policy wizard expiration ISO formatting"
Assert-Contains $wizard "VerticalAlignment = VerticalAlignment.Top" "Policy wizard compact score fields"
Assert-Contains $scopeCatalog "internal static class PolicyScopeCatalog" "Policy scope catalog"
Assert-Contains $scopeCatalog "remote_endpoint_policies" "Remote endpoint catalog section"
Assert-Contains $scopeCatalog "detection_policies" "Detection catalog section"
Assert-Contains $scopeCatalog "response_policy" "Response catalog section"
Assert-Contains $scopeCatalog "FallbackActions" "Unknown scope safe fallback"
Assert-Contains $scopeCatalog "IsScoreRelevant" "Shared score relevance rules"
Assert-Contains $scopeCatalog "IsDeltaRelevant" "Shared delta relevance rules"
Assert-Contains $scopeCatalog "DefaultScoreForAction" "Shared default score rules"
Assert-Contains $scopeCatalog "ActionHelpText" "Shared action help text"
Assert-Contains $scopeCatalog "ScopeHelpText" "Shared policy type help text"
Assert-Contains $scopeCatalog "AllAlphabetical" "Shared alphabetical scope list"
Assert-Contains $scopeCatalog "OrderBy(action => action" "Shared alphabetical action list"
Assert-Contains $guiJson "internal static class GuiJson" "Shared GUI JSON helper"
Assert-Contains $guiJson "IndentedOptions" "Shared indented JSON options"
Assert-Contains $guiJson "CaseInsensitiveOptions" "Shared case-insensitive JSON options"

Assert-Contains $configXaml 'ToolTipService.ToolTip="AlertOnly is the safe default.' "Response field help"
Assert-Contains $configXaml 'ip-api.com hook' "ip-api field"
Assert-Contains $configXaml 'non-commercial only' "External geo hook licensing help"
Assert-Contains $configXaml 'ToolTipService.ToolTip="Environment variable name only.' "AI env var field help"
Assert-Contains $configStore "ArcaneConfigMetadata" "Config metadata model"
Assert-Contains $configStore "DangerLevel" "Config danger metadata"
Assert-Contains $configStore "PrivacyNote" "Config privacy metadata"
Assert-Contains $configStore "HelpText" "Config help text"

$settings = Get-Content -LiteralPath (Join-Path $root "src\ArcaneEDR.Gui\Services\GuiStartupSettings.cs") -Raw
Assert-Contains $settings "public bool PolicyHideDisabled { get; set; } = true;" "Policy hide disabled saved default"

Write-Host "GUI policy oracle passed."
