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

$xaml = Get-Content -LiteralPath (Join-Path $root "src\ArcaneEDR.Gui\Pages\PolicyPage.xaml") -Raw
$code = Get-Content -LiteralPath (Join-Path $root "src\ArcaneEDR.Gui\Pages\PolicyPage.xaml.cs") -Raw
$store = Get-Content -LiteralPath (Join-Path $root "src\ArcaneEDR.Gui\Services\ArcanePolicyStore.cs") -Raw
$configXaml = Get-Content -LiteralPath (Join-Path $root "src\ArcaneEDR.Gui\Pages\ConfigurationPage.xaml") -Raw
$configStore = Get-Content -LiteralPath (Join-Path $root "src\ArcaneEDR.Gui\Services\ArcaneConfigFile.cs") -Raw

Assert-Contains $xaml 'TabView x:Name="PolicyTabs"' "Policy page tabs"
Assert-Contains $xaml 'Header="Entries"' "Policy entries tab"
Assert-Contains $xaml 'x:Name="PolicyEntriesList"' "Policy entries list"
Assert-Contains $xaml 'x:Name="PolicyScopeFilterBox"' "Policy scope filter"
Assert-Contains $xaml 'x:Name="PolicySearchBox"' "Policy search"
Assert-Contains $xaml 'x:Name="SelectedPolicyDetailText"' "Selected policy detail"
Assert-Contains $xaml 'Header="Inspect Output"' "Policy inspect output tab"
Assert-Contains $xaml 'TextBlock x:Name="PolicyOutputText" Style="{StaticResource ConsoleTextStyle}"' "Policy output text"
Assert-Contains $xaml 'Header="Raw JSON"' "Policy raw JSON tab"
Assert-Contains $xaml 'x:Name="PolicyRawText"' "Policy raw JSON text"

Assert-Contains $code "ArcanePolicyStore.Load" "Policy store load"
Assert-Contains $code "ApplyPolicyFilters" "Policy filter handler"
Assert-Contains $code "ShowSelectedPolicyEntry" "Selected policy details"
Assert-Contains $code "--policy-inspect" "Policy inspect command"
Assert-Contains $code "GuiCommandStatus.RunAsync" "Policy command status"

Assert-Contains $store "remote_endpoint_policies" "Remote endpoint policy parsing"
Assert-Contains $store "detection_policies" "Detection policy parsing"
Assert-Contains $store "response_policy" "Response policy parsing"
Assert-Contains $store "allowlists" "Allowlist parsing"
Assert-Contains $store "blocklists" "Blocklist parsing"
Assert-Contains $store "ItemCount" "Policy item count"

Assert-Contains $configXaml 'ToolTipService.ToolTip="AlertOnly is the safe default.' "Response field help"
Assert-Contains $configXaml 'ip-api.com hook' "ip-api field"
Assert-Contains $configXaml 'non-commercial only' "External geo hook licensing help"
Assert-Contains $configXaml 'ToolTipService.ToolTip="Environment variable name only.' "AI env var field help"
Assert-Contains $configStore "ArcaneConfigMetadata" "Config metadata model"
Assert-Contains $configStore "DangerLevel" "Config danger metadata"
Assert-Contains $configStore "PrivacyNote" "Config privacy metadata"
Assert-Contains $configStore "HelpText" "Config help text"

Write-Host "GUI policy oracle passed."
