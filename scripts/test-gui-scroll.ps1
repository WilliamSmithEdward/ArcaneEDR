$ErrorActionPreference = "Stop"

$root = Split-Path -Parent $PSScriptRoot

function Fail-Test {
    param([string]$Message)
    throw $Message
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

function Assert-Equal {
    param(
        [int]$Expected,
        [int]$Actual,
        [string]$Name
    )

    if ($Expected -ne $Actual) {
        Fail-Test "$Name expected $Expected, got $Actual."
    }
}

$mainWindow = Get-Content -LiteralPath (Join-Path $root "src\ArcaneEDR.Gui\MainWindow.xaml.cs") -Raw
Assert-NotContains $mainWindow "ScrollInputRouter.Attach" "Main window"
Assert-NotContains $mainWindow "PointerWheelChangedEvent" "Main window"

$routerPath = Join-Path $root "src\ArcaneEDR.Gui\Services\ScrollInputRouter.cs"
if (Test-Path -LiteralPath $routerPath) {
    Fail-Test "Global ScrollInputRouter should not exist; page scrolling must stay scoped to the active page."
}

$pageScrollBehaviorPath = Join-Path $root "src\ArcaneEDR.Gui\Controls\PageScrollBehavior.cs"
if (-not (Test-Path -LiteralPath $pageScrollBehaviorPath)) {
    Fail-Test "PageScrollBehavior should exist for scoped page-level wheel handling."
}

$pageScrollBehavior = Get-Content -LiteralPath $pageScrollBehaviorPath -Raw
Assert-Contains $pageScrollBehavior "FindNearestNestedScrollViewer" "PageScrollBehavior"
Assert-Contains $pageScrollBehavior "PointerWheelChangedEvent" "PageScrollBehavior"
Assert-Contains $pageScrollBehavior "AttachToCurrentContent" "PageScrollBehavior"
Assert-Contains $pageScrollBehavior "OwnerScrollViewerProperty" "PageScrollBehavior"
Assert-Contains $pageScrollBehavior "ChangeView(" "PageScrollBehavior"
Assert-Contains $pageScrollBehavior "AbsorbBoundaryWheel" "PageScrollBehavior"
Assert-Contains $pageScrollBehavior "IsAtDirectionalEdge" "PageScrollBehavior"
Assert-Contains $pageScrollBehavior "EnsureHitTestableContent" "PageScrollBehavior"
Assert-Contains $pageScrollBehavior "CancelDirectManipulations" "PageScrollBehavior"
Assert-Contains $pageScrollBehavior "Colors.Transparent" "PageScrollBehavior"
Assert-Contains $pageScrollBehavior "OffsetTolerance" "PageScrollBehavior"
Assert-NotContains $pageScrollBehavior "scrollViewer.AddHandler" "PageScrollBehavior"
Assert-NotContains $pageScrollBehavior "TryScroll" "PageScrollBehavior"

$pageText = ""
foreach ($file in Get-ChildItem -LiteralPath (Join-Path $root "src\ArcaneEDR.Gui\Pages") -Filter "*.xaml") {
    $text = Get-Content -LiteralPath $file.FullName -Raw
    $scrollViewers = [regex]::Matches($text, "<ScrollViewer\b(?<attrs>[^>]*)>")
    foreach ($match in $scrollViewers) {
        $attrs = $match.Groups["attrs"].Value
        $isPageScroller = $attrs.IndexOf("PageScrollViewerStyle", [System.StringComparison]::OrdinalIgnoreCase) -ge 0
        $isAlertTableHorizontalScroller = $attrs.IndexOf('x:Name="AlertTableHorizontalScroller"', [System.StringComparison]::OrdinalIgnoreCase) -ge 0

        if ($isPageScroller) {
            if ($attrs.IndexOf('PageScrollBehavior.UseReliableWheel="True"', [System.StringComparison]::OrdinalIgnoreCase) -lt 0) {
                Fail-Test "$($file.Name) contains a page ScrollViewer without reliable wheel handling."
            }
        } elseif ($isAlertTableHorizontalScroller) {
            foreach ($needle in @(
                'HorizontalScrollMode="Enabled"',
                'VerticalScrollMode="Disabled"',
                'IsHorizontalScrollChainingEnabled="False"',
                'IsVerticalScrollChainingEnabled="False"'
            )) {
                if ($attrs.IndexOf($needle, [System.StringComparison]::OrdinalIgnoreCase) -lt 0) {
                    Fail-Test "$($file.Name) AlertTableHorizontalScroller should contain $needle."
                }
            }
        } else {
            Fail-Test "$($file.Name) contains an unclassified ScrollViewer."
        }
    }

    $pageText += [Environment]::NewLine + $text
}

Assert-Contains $pageText "controls:PageScrollBehavior.UseReliableWheel=`"True`"" "Page XAML"

$appResources = Get-Content -LiteralPath (Join-Path $root "src\ArcaneEDR.Gui\App.xaml") -Raw
foreach ($needle in @(
    'x:Key="PageScrollViewerStyle"',
    'HorizontalScrollBarVisibility" Value="Disabled"',
    'HorizontalScrollMode" Value="Disabled"',
    'IsHorizontalScrollChainingEnabled" Value="False"',
    'IsScrollInertiaEnabled" Value="False"',
    'IsVerticalScrollChainingEnabled" Value="False"',
    'VerticalScrollMode" Value="Enabled"',
    'ZoomMode" Value="Disabled"'
)) {
    Assert-Contains $appResources $needle "Page scroll style"
}

$consoleTextBoxUses = ([regex]::Matches($pageText, "ConsoleTextBoxStyle")).Count
Assert-Equal 0 $consoleTextBoxUses "Read-only alert and output panes should not use nested ConsoleTextBoxStyle scroll hosts"
Assert-Contains $pageText 'TextBlock x:Name="SelectedAlertMetadataText" Style="{StaticResource ConsoleTextStyle}"' "Selected alert metadata"
Assert-Contains $pageText 'TextBlock x:Name="SelectedAlertEvidenceText" Style="{StaticResource ConsoleTextStyle}"' "Selected alert evidence"

$readOnlyOutputNames = @(
    "OutputText",
    "VolumeText",
    "RecentAlertsText",
    "PathText",
    "ValidationText",
    "ReportOutputText",
    "MaintenanceOutputText",
    "PolicyOutputText",
    "AboutOutputText",
    "SettingsPathText"
)
foreach ($name in $readOnlyOutputNames) {
    Assert-Contains $pageText "TextBlock x:Name=`"$name`" Style=`"{StaticResource ConsoleTextStyle}`"" "$name output pane"
}

Write-Host "GUI scroll oracle passed."
