param(
    [string]$Configuration = "Release",
    [string]$RuntimeIdentifier = "win-x64",
    [string]$OutputPath = "",
    [switch]$NoClean
)

$ErrorActionPreference = "Stop"

$root = Split-Path -Parent $PSScriptRoot
. (Join-Path $PSScriptRoot "arcane-script-common.ps1")

function Clear-StaleInstallAgentWorkspaceRoot {
    param([string]$GuiOutputPath)

    if (!((Split-Path -Leaf $GuiOutputPath).Equals("gui", [System.StringComparison]::OrdinalIgnoreCase))) {
        return
    }

    $installRoot = Split-Path -Parent $GuiOutputPath
    if ([string]::IsNullOrWhiteSpace($installRoot)) { return }

    $configPath = Join-Path (Join-Path $installRoot "config") "ArcaneEDR.config"
    if (!(Test-Path -LiteralPath $configPath)) { return }

    Clear-StaleAgentWorkspaceRoot -Path $configPath -SourceRoot $root
}

$dotnet = Join-Path $env:ProgramFiles "dotnet\dotnet.exe"
if (!(Test-Path $dotnet)) {
    $dotnet = "dotnet"
}

$project = Join-Path $root "src\ArcaneEDR.Gui\ArcaneEDR.Gui.csproj"
$projectDirectory = Split-Path -Parent $project
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

if (!$NoClean) {
    $projectDirectoryFullPath = [System.IO.Path]::GetFullPath($projectDirectory)
    foreach ($childName in @("bin", "obj")) {
        $cleanTarget = Join-Path $projectDirectory $childName
        if (!(Test-Path -LiteralPath $cleanTarget)) { continue }

        $cleanTargetFullPath = [System.IO.Path]::GetFullPath($cleanTarget)
        if (!$cleanTargetFullPath.StartsWith($projectDirectoryFullPath, [System.StringComparison]::OrdinalIgnoreCase)) {
            throw "Refusing to clean path outside GUI project directory: $cleanTargetFullPath"
        }

        Remove-Item -LiteralPath $cleanTargetFullPath -Recurse -Force
    }
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
        $parent = Split-Path -Parent $outputFullPath
        if ([string]::IsNullOrWhiteSpace($parent) -or $outputFullPath.TrimEnd('\') -eq [System.IO.Path]::GetPathRoot($outputFullPath).TrimEnd('\')) {
            throw "Refusing to clean unsafe GUI output path: $outputFullPath"
        }

        Remove-Item -LiteralPath $outputFullPath -Recurse -Force
    }
    New-Item -ItemType Directory -Force -Path $outputFullPath | Out-Null
    Copy-Item -Path (Join-Path $buildOutput "*") -Destination $outputFullPath -Recurse -Force
}

$assetSource = Join-Path $root "src\ArcaneEDR.Gui\Assets"
$assetDestination = Join-Path $outputFullPath "Assets"
if (Test-Path $assetSource) {
    New-Item -ItemType Directory -Force -Path $assetDestination | Out-Null
    Copy-Item -Path (Join-Path $assetSource "*") -Destination $assetDestination -Force
}

& (Join-Path $PSScriptRoot "test-gui-payload.ps1") -Path $outputFullPath
Clear-StaleInstallAgentWorkspaceRoot -GuiOutputPath $outputFullPath

Write-Host "Built self-contained GUI to $outputFullPath"
