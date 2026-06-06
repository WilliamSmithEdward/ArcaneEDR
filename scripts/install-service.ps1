param(
    [string]$ServiceName = "",
    [string]$DisplayName = ""
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
$runtimeConfig = Resolve-ConfigPath `
    -Primary (Join-Path $root "config\ArcaneEDR.config") `
    -Example (Join-Path $root "config\ArcaneEDR.example.config")
$deploymentConfig = Resolve-ConfigPath `
    -Primary (Join-Path $root "config\Deployment.config") `
    -Example (Join-Path $root "config\Deployment.example.config")
$executableName = Get-ConfigValue -Path $deploymentConfig -Name "ExecutableName" -Default "ArcaneEDR.exe"
$exe = Join-Path $root "bin\$executableName"
if ([string]::IsNullOrWhiteSpace($ServiceName)) {
    $ServiceName = Get-ConfigValue -Path $runtimeConfig -Name "ServiceName" -Default "ArcaneEDR"
}
if ([string]::IsNullOrWhiteSpace($DisplayName)) {
    $DisplayName = Get-ConfigValue -Path $runtimeConfig -Name "ServiceDisplayName" -Default $ServiceName
}
$description = Get-ConfigValue -Path $runtimeConfig -Name "ServiceDescription" -Default "Monitors suspicious ingress and egress network activity and sends security alerts."
$logDir = Get-ConfigValue -Path $runtimeConfig -Name "LogDirectory" -Default (Join-Path $env:ProgramData "ArcaneEDR\logs")

$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (!$principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Run this script from an elevated PowerShell session."
}

if (!(Test-Path $exe)) {
    & (Join-Path $PSScriptRoot "build.ps1")
}

New-Item -ItemType Directory -Force -Path $logDir | Out-Null

if (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue) {
    throw "Service '$ServiceName' already exists. Run uninstall-service.ps1 first."
}

New-Service -Name $ServiceName `
    -BinaryPathName "`"$exe`"" `
    -DisplayName $DisplayName `
    -Description $description `
    -StartupType Automatic

sc.exe failure $ServiceName reset= 86400 actions= restart/60000/restart/60000/restart/300000 | Out-Host
sc.exe failureflag $ServiceName 1 | Out-Host

Start-Service -Name $ServiceName
Write-Host "Installed and started $ServiceName"
