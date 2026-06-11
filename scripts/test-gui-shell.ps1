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

Assert-NotContains $mainWindow 'PaneTitle="Arcane EDR"' "Navigation pane branding"
Assert-Contains $mainWindow '<NavigationView.PaneHeader>' "Navigation pane header"
Assert-Contains $mainWindow 'MinHeight="72"' "Navigation pane header height"
Assert-Contains $mainWindow 'Margin="14,12,12,18"' "Navigation pane header margin"
Assert-Contains $mainWindow '<ColumnDefinition Width="52" />' "Navigation pane logo column"
Assert-Contains $mainWindow 'Width="48"' "Navigation pane logo width"
Assert-Contains $mainWindow 'HorizontalAlignment="Left"' "Navigation pane logo alignment"
Assert-Contains $mainWindow 'MaxLines="1"' "Navigation pane title line clamp"

Write-Host "GUI shell oracle passed."
