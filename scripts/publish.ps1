param(
    [string]$ApplicationName = "",
    [string]$DestinationRoot = "",
    [switch]$OverwriteConfig,
    [switch]$OverwriteDeploymentConfig
)

$ErrorActionPreference = "Stop"

function Get-ConfigValue {
    param(
        [string]$Path,
        [string]$Name,
        [string]$Default
    )

    if (Test-Path $Path) {
        foreach ($rawLine in Get-Content -Path $Path) {
            $line = $rawLine.Trim()
            if ($line.Length -eq 0 -or $line.StartsWith("#")) { continue }
            $equals = $line.IndexOf("=")
            if ($equals -le 0) { continue }
            $key = $line.Substring(0, $equals).Trim()
            if ($key.Equals($Name, [System.StringComparison]::OrdinalIgnoreCase)) {
                return $line.Substring($equals + 1).Trim()
            }
        }
    }

    return $Default
}

function Resolve-ConfigPath {
    param(
        [string]$Primary,
        [string]$Example
    )

    if (Test-Path $Primary) { return $Primary }
    return $Example
}

$root = Split-Path -Parent $PSScriptRoot
$deploymentConfig = Resolve-ConfigPath `
    -Primary (Join-Path $root "config\Deployment.config") `
    -Example (Join-Path $root "config\Deployment.example.config")
if ([string]::IsNullOrWhiteSpace($ApplicationName)) {
    $ApplicationName = Get-ConfigValue -Path $deploymentConfig -Name "ApplicationName" -Default "ArcaneEDR"
}
if ([string]::IsNullOrWhiteSpace($DestinationRoot)) {
    $DestinationRoot = Get-ConfigValue -Path $deploymentConfig -Name "DestinationRoot" -Default (Join-Path $env:ProgramData "ArcaneEDR")
}
$executableName = Get-ConfigValue -Path $deploymentConfig -Name "ExecutableName" -Default "ArcaneEDR.exe"
$destination = Join-Path $DestinationRoot $ApplicationName
$bin = Join-Path $destination "bin"
$config = Join-Path $destination "config"
$scripts = Join-Path $destination "scripts"
$docs = Join-Path $destination "docs"
$tools = Join-Path $destination "tools"

& (Join-Path $PSScriptRoot "build.ps1")

New-Item -ItemType Directory -Force -Path $bin, $config, $scripts, $docs, $tools | Out-Null

Copy-Item -LiteralPath (Join-Path $root "bin\$executableName") -Destination $bin -Force
$sourceConfig = Join-Path $root "config\ArcaneEDR.config"
if (!(Test-Path $sourceConfig)) {
    $sourceConfig = Join-Path $root "config\ArcaneEDR.example.config"
}
$destinationConfig = Join-Path $config "ArcaneEDR.config"
if ($OverwriteConfig -or !(Test-Path $destinationConfig)) {
    Copy-Item -LiteralPath $sourceConfig -Destination $destinationConfig -Force
} else {
    Copy-Item -LiteralPath $sourceConfig -Destination (Join-Path $config "ArcaneEDR.example.config") -Force
    Write-Host "Preserved existing config: $destinationConfig"
    Write-Host "Wrote source config example: $(Join-Path $config "ArcaneEDR.example.config")"
}
$sourceDeploymentConfig = $deploymentConfig
$destinationDeploymentConfig = Join-Path $config "Deployment.config"
if ($OverwriteDeploymentConfig -or !(Test-Path $destinationDeploymentConfig)) {
    Copy-Item -LiteralPath $sourceDeploymentConfig -Destination $destinationDeploymentConfig -Force
} else {
    Copy-Item -LiteralPath $sourceDeploymentConfig -Destination (Join-Path $config "Deployment.example.config") -Force
    Write-Host "Preserved existing deployment config: $destinationDeploymentConfig"
    Write-Host "Wrote source deployment config example: $(Join-Path $config "Deployment.example.config")"
}
Copy-Item -LiteralPath (Join-Path $root "config\arcaneedr-sysmon.xml") -Destination $config -Force
Copy-Item -LiteralPath (Join-Path $root "config\custom-rules.json") -Destination $config -Force
Copy-Item -LiteralPath (Join-Path $root "config\policy-rules.example.json") -Destination $config -Force
Copy-Item -LiteralPath (Join-Path $root "README.md") -Destination $destination -Force
Copy-Item -Path (Join-Path $root "docs\*.md") -Destination $docs -Force
Copy-Item -Path (Join-Path $root "scripts\*.ps1") -Destination $scripts -Force
Copy-Item -Path (Join-Path $root "scripts\*.cmd") -Destination $scripts -Force

Write-Host "Published to $destination"
Write-Host "Executable: $(Join-Path $bin $executableName)"
