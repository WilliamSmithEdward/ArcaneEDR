param(
    [Parameter(Mandatory = $true)]
    [string]$Path,

    [int]$MaxSkewSeconds = 600
)

$ErrorActionPreference = "Stop"

$root = Split-Path -Parent $PSScriptRoot
$guiSource = Join-Path $root "src\ArcaneEDR.Gui"
$pageSource = Join-Path $guiSource "Pages"
$resolvedPath = [System.IO.Path]::GetFullPath($Path)

if (!(Test-Path -LiteralPath $resolvedPath -PathType Container)) {
    throw "GUI payload directory not found: $resolvedPath"
}

$required = New-Object System.Collections.Generic.List[string]
$required.Add("ArcaneEDR.Gui.exe")
$required.Add("ArcaneEDR.Gui.dll")
$required.Add("ArcaneEDR.Gui.pri")
$required.Add("App.xbf")
$required.Add("MainWindow.xbf")

foreach ($page in Get-ChildItem -LiteralPath $pageSource -Filter "*.xaml" -File) {
    $required.Add((Join-Path "Pages" ($page.BaseName + ".xbf")))
}

$files = New-Object System.Collections.Generic.List[System.IO.FileInfo]
$missing = New-Object System.Collections.Generic.List[string]
foreach ($relative in $required) {
    $fullPath = Join-Path $resolvedPath $relative
    if (!(Test-Path -LiteralPath $fullPath -PathType Leaf)) {
        $missing.Add($relative)
        continue
    }

    $item = Get-Item -LiteralPath $fullPath
    if ($item.Length -le 0) {
        throw "GUI payload file is empty: $fullPath"
    }

    $files.Add($item)
}

if ($missing.Count -gt 0) {
    throw "GUI payload is missing required file(s): " + ($missing -join ", ")
}

$oldest = $files | Sort-Object LastWriteTimeUtc | Select-Object -First 1
$newest = $files | Sort-Object LastWriteTimeUtc -Descending | Select-Object -First 1
$skewSeconds = [Math]::Abs(($newest.LastWriteTimeUtc - $oldest.LastWriteTimeUtc).TotalSeconds)
if ($skewSeconds -gt $MaxSkewSeconds) {
    throw ("GUI payload timestamp skew is {0:N1}s, above {1}s. Oldest={2} ({3:o}); Newest={4} ({5:o}). This usually means stale XAML .xbf resources were left beside a newer DLL." -f `
        $skewSeconds,
        $MaxSkewSeconds,
        $oldest.FullName,
        $oldest.LastWriteTimeUtc,
        $newest.FullName,
        $newest.LastWriteTimeUtc)
}

Write-Host ("GUI payload validated: {0} file(s), skew {1:N1}s, path={2}" -f $files.Count, $skewSeconds, $resolvedPath)
