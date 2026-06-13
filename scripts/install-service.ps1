param(
    [string]$ServiceName = "",
    [string]$DisplayName = ""
)

$ErrorActionPreference = "Stop"

. (Join-Path $PSScriptRoot "arcane-script-common.ps1")

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
$description = Get-ConfigValue -Path $runtimeConfig -Name "ServiceDescription" -Default "Monitors host, process, persistence, PowerShell, Sysmon, and network activity for suspicious behavior on unattended agent workstations."
$logDir = Get-ConfigValue -Path $runtimeConfig -Name "LogDirectory" -Default (Join-Path $env:ProgramData "ArcaneEDR\logs")

if (!(Test-IsAdministrator)) {
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
