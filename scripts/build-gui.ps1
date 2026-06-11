param(
    [string]$Configuration = "Release",
    [string]$RuntimeIdentifier = "win-x64",
    [string]$OutputPath = ""
)

$ErrorActionPreference = "Stop"

$root = Split-Path -Parent $PSScriptRoot
$dotnet = Join-Path $env:ProgramFiles "dotnet\dotnet.exe"
if (!(Test-Path $dotnet)) {
    $dotnet = "dotnet"
}

$project = Join-Path $root "src\ArcaneEDR.Gui\ArcaneEDR.Gui.csproj"
if ([System.String]::IsNullOrWhiteSpace($OutputPath)) {
    $OutputPath = Join-Path $root ("artifacts\gui\" + $RuntimeIdentifier)
}
elseif (![System.IO.Path]::IsPathRooted($OutputPath)) {
    $OutputPath = Join-Path $root $OutputPath
}

New-Item -ItemType Directory -Force -Path $OutputPath | Out-Null

& $dotnet publish $project `
    -c $Configuration `
    -p:Platform=x64 `
    -r $RuntimeIdentifier `
    --self-contained true `
    -o $OutputPath

if ($LASTEXITCODE -ne 0) {
    throw "GUI publish failed with exit code $LASTEXITCODE."
}

$assetSource = Join-Path $root "src\ArcaneEDR.Gui\Assets"
$assetDestination = Join-Path $OutputPath "Assets"
if (Test-Path $assetSource) {
    New-Item -ItemType Directory -Force -Path $assetDestination | Out-Null
    Copy-Item -Path (Join-Path $assetSource "*") -Destination $assetDestination -Force
}

Write-Host "Published GUI to $OutputPath"
