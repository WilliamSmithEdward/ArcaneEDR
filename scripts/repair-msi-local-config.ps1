param(
    [string]$InstallRoot = "",
    [string]$SourceRoot = "",
    [string]$LegacyRoot = "C:\Applications\ArcaneEDR",
    [switch]$NoRestart,
    [switch]$RegisterAdminTasks
)

$ErrorActionPreference = "Stop"

. (Join-Path $PSScriptRoot "arcane-script-common.ps1")

function Read-ConfigMap {
    param([string]$Path)

    $map = New-Object "System.Collections.Generic.Dictionary[string,string]" ([System.StringComparer]::OrdinalIgnoreCase)
    if (!(Test-Path -LiteralPath $Path)) {
        return $map
    }

    foreach ($rawLine in Get-Content -LiteralPath $Path) {
        $line = $rawLine.Trim()
        if ($line.Length -eq 0 -or $line.StartsWith("#")) { continue }
        $equals = $line.IndexOf("=")
        if ($equals -le 0) { continue }
        $key = $line.Substring(0, $equals).Trim()
        $value = $line.Substring($equals + 1).Trim()
        $map[$key] = $value
    }

    return $map
}

if (!(Test-IsAdministrator)) {
    throw "Run this script from an elevated PowerShell session."
}

$scriptRoot = $PSScriptRoot
if ([string]::IsNullOrWhiteSpace($SourceRoot)) {
    $SourceRoot = Split-Path -Parent $scriptRoot
}
$SourceRoot = [System.IO.Path]::GetFullPath($SourceRoot)

if ([string]::IsNullOrWhiteSpace($InstallRoot)) {
    $InstallRoot = Join-Path $env:ProgramFiles "Arcane EDR"
}
$InstallRoot = [System.IO.Path]::GetFullPath($InstallRoot)

$installConfigDirectory = Join-Path $InstallRoot "config"
$installConfig = Join-Path $installConfigDirectory "ArcaneEDR.config"
$sourceLocalConfig = Join-Path $SourceRoot "config\ArcaneEDR.config"
$sourceExampleConfig = Join-Path $SourceRoot "config\ArcaneEDR.example.config"
$legacyConfig = Join-Path $LegacyRoot "config\ArcaneEDR.config"

if (!(Test-Path -LiteralPath $installConfig)) {
    throw "Installed ArcaneEDR.config not found at '$installConfig'."
}

$overlayConfig = $sourceLocalConfig
if (!(Test-Path -LiteralPath $overlayConfig)) {
    $overlayConfig = $legacyConfig
}
if (!(Test-Path -LiteralPath $overlayConfig)) {
    throw "No local config found. Expected '$sourceLocalConfig' or '$legacyConfig'."
}

New-Item -ItemType Directory -Force -Path $installConfigDirectory | Out-Null
$stamp = Get-Date -Format "yyyyMMddHHmmss"
$backup = "$installConfig.pre-local-repair-$stamp.bak"
Copy-Item -LiteralPath $installConfig -Destination $backup -Force

$baseMap = Read-ConfigMap -Path $installConfig
$overlayMap = Read-ConfigMap -Path $overlayConfig
$lines = New-Object "System.Collections.Generic.List[string]"
foreach ($line in Get-Content -LiteralPath $installConfig) {
    $lines.Add($line)
}

foreach ($key in $overlayMap.Keys) {
    if ($baseMap.ContainsKey($key)) {
        Set-ConfigLine -Lines $lines -Name $key -Value $overlayMap[$key]
    }
}

$legacyAiKeys = @{
    "OpenAIAnalysisIntervalMinutes" = "AIAnalysisIntervalMinutes"
    "OpenAIAnalysisScoreThreshold" = "AIAnalysisScoreThreshold"
    "OpenAIAnalysisBaselineEmailMinimumScore" = "AIAnalysisBaselineEmailMinimumScore"
    "OpenAIAnalysisMinimumIncludedAlertScore" = "AIAnalysisMinimumIncludedAlertScore"
    "OpenAIAnalysisBaselineMinimumIncludedAlertScore" = "AIAnalysisBaselineMinimumIncludedAlertScore"
    "OpenAIAnalysisExcludedRuleIds" = "AIAnalysisExcludedRuleIds"
    "OpenAIAnalysisModel" = "AIAnalysisModel"
    "OpenAIApiKeyEnvironmentVariable" = "AIAnalysisApiKeyEnvironmentVariable"
    "OpenAIAnalysisApiUrl" = "AIAnalysisApiUrl"
    "OpenAIAnalysisMaxLogLines" = "AIAnalysisMaxLogLines"
    "OpenAIAnalysisMaxAlertLines" = "AIAnalysisMaxAlertLines"
    "OpenAIAnalysisMaxChars" = "AIAnalysisMaxChars"
}
foreach ($legacyKey in $legacyAiKeys.Keys) {
    if ($overlayMap.ContainsKey($legacyKey)) {
        Set-ConfigLine -Lines $lines -Name $legacyAiKeys[$legacyKey] -Value $overlayMap[$legacyKey]
    }
}

$programDataRoot = Join-Path $env:ProgramData "Arcane EDR"
Set-ConfigLine -Lines $lines -Name "LogDirectory" -Value $programDataRoot
Set-ConfigLine -Lines $lines -Name "PolicyFile" -Value "arcane-policy.json"
Set-ConfigLine -Lines $lines -Name "AgentWorkspaceRoots" -Value ""
Set-ConfigLine -Lines $lines -Name "AgentPublishRoots" -Value ($InstallRoot.TrimEnd("\") + "\")

$sourcePolicy = Join-Path $SourceRoot "config\arcane-policy.json"
if (!(Test-Path -LiteralPath $sourcePolicy)) {
    $sourcePolicy = Join-Path $LegacyRoot "config\arcane-policy.json"
}
if (!(Test-Path -LiteralPath $sourcePolicy)) {
    throw "PolicyFile was set to arcane-policy.json, but no source policy file was found."
}

$sourceCountryBlocks = Join-Path $SourceRoot "config\country-ip-blocks"
if (!(Test-Path -LiteralPath $sourceCountryBlocks)) {
    $sourceCountryBlocks = Join-Path $LegacyRoot "config\country-ip-blocks"
}

$repoCountryBlocks = Join-Path $SourceRoot "config\country-ip-blocks"
if (!(Test-Path -LiteralPath $repoCountryBlocks) -and (Test-Path -LiteralPath $sourceCountryBlocks)) {
    Copy-DirectoryContents -Source $sourceCountryBlocks -Destination $repoCountryBlocks | Out-Null
}

Set-Content -LiteralPath $installConfig -Value $lines -Encoding ASCII
if (!(Test-Path -LiteralPath $sourceLocalConfig)) {
    Set-Content -LiteralPath $sourceLocalConfig -Value $lines -Encoding ASCII
}

$destinationPolicy = Join-Path $installConfigDirectory "arcane-policy.json"
$copiedPolicy = Copy-FileIfDifferent -Source $sourcePolicy -Destination $destinationPolicy
$copiedCountryBlocks = Copy-DirectoryContents -Source $sourceCountryBlocks -Destination (Join-Path $installConfigDirectory "country-ip-blocks")

$exe = Join-Path $InstallRoot "bin\ArcaneEDR.exe"
if (!(Test-Path -LiteralPath $exe)) {
    throw "Installed executable not found at '$exe'."
}

Write-Host "Backed up installed config to $backup"
Write-Host "Overlay source: $overlayConfig"
Write-Host "Installed config repaired: $installConfig"
if ($copiedPolicy) {
    Write-Host "Installed policy available: $destinationPolicy"
} else {
    Write-Host "Policy source not found; skipped copy."
}
if ($copiedCountryBlocks) {
    Write-Host "Country blocks copied to installed config directory."
} else {
    Write-Host "Country blocks source not found; skipped copy."
}
Write-Host ""
& $exe --validate-config
if ($LASTEXITCODE -ne 0) {
    throw "Validation failed after config repair. Backup remains at '$backup'."
}

if ($RegisterAdminTasks) {
    $installTasks = Join-Path $SourceRoot "scripts\install-admin-tasks.ps1"
    if (!(Test-Path -LiteralPath $installTasks)) {
        throw "Admin task installer not found at '$installTasks'."
    }
    & $installTasks -InstalledOnly -SourceRoot $InstallRoot -PublishedRoot $InstallRoot
}

if (!$NoRestart) {
    $serviceName = "ArcaneEDR"
    $svc = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
    if ($svc) {
        if ($svc.Status -ne "Stopped") {
            Stop-Service -Name $serviceName -Force
            $svc.WaitForStatus("Stopped", "00:00:30")
        }
        Start-Service -Name $serviceName
        Start-Sleep -Seconds 5
        Get-Service -Name $serviceName
    } else {
        Write-Host "Service '$serviceName' is not installed; skipped restart."
    }
}
