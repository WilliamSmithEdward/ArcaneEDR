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

$xaml = Get-Content -LiteralPath (Join-Path $root "src\ArcaneEDR.Gui\Pages\AlertsPage.xaml") -Raw
$code = Get-Content -LiteralPath (Join-Path $root "src\ArcaneEDR.Gui\Pages\AlertsPage.xaml.cs") -Raw
$store = Get-Content -LiteralPath (Join-Path $root "src\ArcaneEDR.Gui\Services\ArcaneAlertStore.cs") -Raw
$widths = Get-Content -LiteralPath (Join-Path $root "src\ArcaneEDR.Gui\Controls\AlertTableColumnWidths.cs") -Raw
$resizeHandle = Get-Content -LiteralPath (Join-Path $root "src\ArcaneEDR.Gui\Controls\CursorResizeHandle.cs") -Raw

Assert-NotContains $xaml 'x:Name="SortBox"' "Alerts filters"
Assert-NotContains $xaml 'x:Name="SortDirectionBox"' "Alerts filters"

foreach ($column in @("Time", "Rule", "Category", "Score", "Country", "Process", "Company", "Title")) {
    Assert-Contains $xaml "Tag=`"$column`"" "$column header"
    Assert-Contains $xaml "x:Name=`"$column`ColumnResizeHandle`"" "$column resize handle"
    Assert-Contains $widths "public double $column" "$column width binding"
}

Assert-Contains $xaml "AlertTableHorizontalScroller" "Alerts table"
Assert-Contains $xaml "ColumnResizeHandleStyle" "Column resize style"
Assert-Contains $xaml "controls:CursorResizeHandle" "Resize cursor handle"
Assert-Contains $xaml 'CursorShape="SizeWestEast"' "Column resize hover cursor"
Assert-Contains $xaml 'CursorShape="SizeNorthSouth"' "Details resize hover cursor"
Assert-Contains $xaml 'MinWidth="14"' "Sort indicator footprint"
Assert-Contains $xaml "SortHeader_Click" "Header sort"
Assert-Contains $xaml "SystemTimeDisplay" "System time column"
Assert-Contains $xaml "SelectedAlertMetadataText" "Metadata view"
Assert-Contains $xaml "SelectedAlertEvidenceText" "Evidence view"
Assert-Contains $xaml 'Text="Metadata"' "Metadata section label"
Assert-Contains $xaml 'Text="Evidence"' "Evidence section label"

Assert-Contains $code "private string sortColumn = `"Time`"" "Default sort"
Assert-Contains $code "SortHeader_Click" "Header sort handler"
Assert-Contains $code "ConfigureResizeHandles" "Resize handle wiring"
Assert-Contains $code "ColumnResizeHandle_ResizeDelta" "Column resize handler"
Assert-Contains $code "AlertDetailsResizeHandle_ResizeDelta" "Details resize handler"
Assert-Contains $code "BuildSelectedAlertMetadataText" "Metadata formatter"
Assert-Contains $code "BuildSelectedAlertEvidenceText" "Evidence formatter"
Assert-Contains $store "public string SystemTimeDisplay" "Alert record system time"
Assert-Contains $store "TimeZoneInfo.ConvertTimeFromUtc" "System time conversion"
Assert-Contains $resizeHandle "InputSystemCursorShape" "Resize handle shape property"
Assert-Contains $resizeHandle "ProtectedCursor = InputSystemCursor.Create(CursorShape)" "Resize handle hover behavior"
Assert-Contains $resizeHandle "CapturePointer(e.Pointer)" "Resize handle pointer capture"
Assert-Contains $resizeHandle "GetStablePointerPosition" "Stable resize coordinates"
Assert-Contains $resizeHandle "XamlRoot?.Content" "Root-relative resize coordinates"
Assert-Contains $resizeHandle "ResizeDelta?.Invoke" "Resize handle delta event"

Write-Host "GUI alerts oracle passed."
