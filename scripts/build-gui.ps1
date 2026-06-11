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
$targetFramework = $null
foreach ($line in Get-Content -Path $project) {
    if ($line -match '<TargetFramework>([^<]+)</TargetFramework>') {
        $targetFramework = $Matches[1]
        break
    }
}
if ([System.String]::IsNullOrWhiteSpace($targetFramework)) {
    throw "Could not read TargetFramework from $project."
}

if ([System.String]::IsNullOrWhiteSpace($OutputPath)) {
    $OutputPath = Join-Path $root ("artifacts\gui\" + $RuntimeIdentifier)
}
elseif (![System.IO.Path]::IsPathRooted($OutputPath)) {
    $OutputPath = Join-Path $root $OutputPath
}

& $dotnet build $project `
    -c $Configuration `
    -p:Platform=x64 `
    -r $RuntimeIdentifier `
    -p:SelfContained=true `
    -p:WindowsAppSDKSelfContained=true

if ($LASTEXITCODE -ne 0) {
    throw "GUI build failed with exit code $LASTEXITCODE."
}

$buildOutput = Join-Path $root ("src\ArcaneEDR.Gui\bin\x64\$Configuration\$targetFramework\$RuntimeIdentifier")
if (!(Test-Path -LiteralPath $buildOutput)) {
    throw "GUI build output not found: $buildOutput"
}

$outputFullPath = [System.IO.Path]::GetFullPath($OutputPath)
$buildOutputFullPath = [System.IO.Path]::GetFullPath($buildOutput)
if (!$outputFullPath.Equals($buildOutputFullPath, [System.StringComparison]::OrdinalIgnoreCase)) {
    if (Test-Path -LiteralPath $OutputPath) {
        Remove-Item -LiteralPath $OutputPath -Recurse -Force
    }
    New-Item -ItemType Directory -Force -Path $OutputPath | Out-Null
    Copy-Item -Path (Join-Path $buildOutput "*") -Destination $OutputPath -Recurse -Force
}

$assetSource = Join-Path $root "src\ArcaneEDR.Gui\Assets"
$assetDestination = Join-Path $OutputPath "Assets"
if (Test-Path $assetSource) {
    New-Item -ItemType Directory -Force -Path $assetDestination | Out-Null
    Copy-Item -Path (Join-Path $assetSource "*") -Destination $assetDestination -Force
}

Write-Host "Built self-contained GUI to $OutputPath"
