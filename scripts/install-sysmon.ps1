param(
    [string]$SysmonExe = "",
    [string]$ConfigPath = ""
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
if ([string]::IsNullOrWhiteSpace($ConfigPath)) {
    $sysmonConfigFile = Get-ConfigValue -Path $deploymentConfig -Name "SysmonConfigFile" -Default "arcaneedr-sysmon.xml"
    $ConfigPath = Join-Path $root "config\$sysmonConfigFile"
}

if ([string]::IsNullOrWhiteSpace($SysmonExe)) {
    $sysmonExecutableName = Get-ConfigValue -Path $deploymentConfig -Name "SysmonExecutableName" -Default "Sysmon.exe"
    $SysmonExe = Join-Path $root "tools\$sysmonExecutableName"
}

if (!(Test-Path $SysmonExe)) {
    throw "Sysmon executable not found at '$SysmonExe'. Download Sysmon from Microsoft Sysinternals and rerun this script with -SysmonExe."
}

if (!(Test-Path $ConfigPath)) {
    throw "Sysmon config not found at '$ConfigPath'."
}

& $SysmonExe -accepteula -i $ConfigPath
if ($LASTEXITCODE -ne 0) {
    throw "Sysmon install failed with exit code $LASTEXITCODE. Run this script from an elevated PowerShell session."
}
Write-Host "Sysmon installed with $ConfigPath"
