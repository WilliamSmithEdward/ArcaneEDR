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
$mainWindowCode = Get-Content -LiteralPath (Join-Path $root "src\ArcaneEDR.Gui\MainWindow.xaml.cs") -Raw
$appCode = Get-Content -LiteralPath (Join-Path $root "src\ArcaneEDR.Gui\App.xaml.cs") -Raw
$settingsXaml = Get-Content -LiteralPath (Join-Path $root "src\ArcaneEDR.Gui\Pages\SettingsPage.xaml") -Raw
$settingsCode = Get-Content -LiteralPath (Join-Path $root "src\ArcaneEDR.Gui\Pages\SettingsPage.xaml.cs") -Raw
$startupSettings = Get-Content -LiteralPath (Join-Path $root "src\ArcaneEDR.Gui\Services\GuiStartupSettings.cs") -Raw
$homeXaml = Get-Content -LiteralPath (Join-Path $root "src\ArcaneEDR.Gui\Pages\HomePage.xaml") -Raw
$homeCode = Get-Content -LiteralPath (Join-Path $root "src\ArcaneEDR.Gui\Pages\HomePage.xaml.cs") -Raw
$alertStoreCode = Get-Content -LiteralPath (Join-Path $root "src\ArcaneEDR.Gui\Services\ArcaneAlertStore.cs") -Raw
$validationView = Get-Content -LiteralPath (Join-Path $root "src\ArcaneEDR.Gui\Services\ArcaneValidationView.cs") -Raw
$stateReader = Get-Content -LiteralPath (Join-Path $root "src\ArcaneEDR.Gui\Services\ArcaneStateReader.cs") -Raw
$commandStatus = Get-Content -LiteralPath (Join-Path $root "src\ArcaneEDR.Gui\Services\GuiCommandStatus.cs") -Raw
$reportsCode = Get-Content -LiteralPath (Join-Path $root "src\ArcaneEDR.Gui\Pages\ReportsPage.xaml.cs") -Raw
$maintenanceCode = Get-Content -LiteralPath (Join-Path $root "src\ArcaneEDR.Gui\Pages\MaintenancePage.xaml.cs") -Raw
$configCode = Get-Content -LiteralPath (Join-Path $root "src\ArcaneEDR.Gui\Pages\ConfigurationPage.xaml.cs") -Raw

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
Assert-Contains $appCode 'args.Handled = true' "XAML exception handler"
Assert-Contains $mainWindowCode 'NavFrame.NavigationFailed += NavFrame_NavigationFailed' "Frame navigation failure handler"
Assert-Contains $mainWindowCode 'args.Handled = true' "Frame navigation failure handled"
Assert-Contains $mainWindowCode 'ApplyTitleBarColors' "Title bar color hook"
Assert-Contains $mainWindowCode 'titleBar.BackgroundColor = Colors.Black' "Black active title bar"
Assert-Contains $mainWindowCode 'titleBar.ButtonBackgroundColor = Colors.Black' "Black title bar buttons"
Assert-Contains $mainWindowCode 'titleBar.ButtonForegroundColor = Colors.White' "Light title bar button icons"

Assert-Contains $homeXaml 'ValidationHeadingText' "Overview validation heading"
Assert-Contains $homeXaml 'StatusHeadingText' "Overview plain status heading"
Assert-Contains $homeXaml 'NextActionText' "Overview next action"
Assert-Contains $homeCode 'ArcaneValidationView.BuildOverviewText' "Overview validation formatter"
Assert-Contains $homeCode 'BuildStatusHeading' "Overview status summary"
Assert-Contains $homeCode 'BuildNextAction' "Overview next action builder"
Assert-Contains $homeCode 'HomePage_Unloaded' "Overview unload cancellation"
Assert-Contains $homeCode 'CancellationTokenSource' "Overview refresh cancellation"
Assert-Contains $homeCode 'IsCurrentRefresh' "Overview stale refresh guard"
Assert-Contains $alertStoreCode 'validation.ErrorCount' "Overview recommendation validation parser"
Assert-Contains $validationView 'ArcaneCommandRunner.RunAsync("--validate-config", "--json")' "Validation JSON command"
Assert-Contains $stateReader 'ArcaneCommandRunner.RunAsync("--health", "--json")' "Health JSON command"
Assert-Contains $validationView 'Validation summary:' "Validation summary parser"
Assert-Contains $validationView 'No configuration blockers found.' "Warning-only validation copy"
Assert-Contains $validationView 'StartsWith("Validation summary:"' "Precise summary line match"
Assert-Contains $validationView 'Maintenance > Validate Admin' "Admin validation warning guidance"
Assert-NotContains $homeCode 'IndexOf("error(s)"' "Validation false-positive parser"
Assert-NotContains $homeCode 'IndexOf("summary"' "Validation broad summary parser"

Assert-Contains $commandStatus 'button.IsEnabled = false' "Command feedback disables initiating button"
Assert-Contains $commandStatus 'Command failed:' "Command feedback error text"
Assert-Contains $reportsCode 'GuiCommandStatus.RunAsync' "Reports command feedback"
Assert-Contains $maintenanceCode 'RunMaintenanceAsync' "Maintenance command feedback"
Assert-Contains $configCode 'Validating configuration...' "Configuration validation status"

Write-Host "GUI shell oracle passed."
