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

$mainWindow = Get-Content -LiteralPath (Join-Path $root "src\ArcaneEDR.Gui\MainWindow.xaml") -Raw
$appCode = Get-Content -LiteralPath (Join-Path $root "src\ArcaneEDR.Gui\App.xaml.cs") -Raw
$settingsXaml = Get-Content -LiteralPath (Join-Path $root "src\ArcaneEDR.Gui\Pages\SettingsPage.xaml") -Raw
$settingsCode = Get-Content -LiteralPath (Join-Path $root "src\ArcaneEDR.Gui\Pages\SettingsPage.xaml.cs") -Raw
$startupSettings = Get-Content -LiteralPath (Join-Path $root "src\ArcaneEDR.Gui\Services\GuiStartupSettings.cs") -Raw

Assert-NotContains $mainWindow 'PaneTitle="Arcane EDR"' "Navigation pane branding"
Assert-Contains $mainWindow '<NavigationView.PaneHeader>' "Navigation pane header"
Assert-Contains $mainWindow 'MinHeight="72"' "Navigation pane header height"
Assert-Contains $mainWindow 'Margin="14,12,12,18"' "Navigation pane header margin"
Assert-Contains $mainWindow '<ColumnDefinition Width="52" />' "Navigation pane logo column"
Assert-Contains $mainWindow 'Width="48"' "Navigation pane logo width"
Assert-Contains $mainWindow 'HorizontalAlignment="Left"' "Navigation pane logo alignment"
Assert-Contains $mainWindow 'MaxLines="1"' "Navigation pane title line clamp"

Assert-Contains $settingsXaml 'StartOnLoginSwitch' "Settings startup toggle"
Assert-Contains $settingsXaml 'StartMinimizedSwitch' "Settings minimized toggle"
Assert-Contains $settingsCode 'GuiStartupSettings.SaveAndApply' "Settings startup save"
Assert-Contains $startupSettings 'StartOnWindowsLogin { get; set; } = true' "Startup default"
Assert-Contains $startupSettings 'StartMinimizedOnWindowsLogin { get; set; } = true' "Startup minimized default"
Assert-Contains $startupSettings 'Software\Microsoft\Windows\CurrentVersion\Run' "Startup Run key"
Assert-Contains $startupSettings '"--startup"' "Startup argument"
Assert-Contains $startupSettings 'Registry.CurrentUser' "Current-user startup registration"
Assert-Contains $appCode 'GuiStartupSettings.IsStartupLaunch' "Startup launch detection"
Assert-Contains $appCode '!isWindowsLoginStartup || !settings.StartMinimizedOnWindowsLogin' "Normal launch shows window"
Assert-Contains $appCode '_window.ShowAndActivate();' "Normal launch window activation"

Write-Host "GUI shell oracle passed."
