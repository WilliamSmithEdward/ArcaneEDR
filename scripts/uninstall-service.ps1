param(
    [string]$ServiceName = ""
)

$ErrorActionPreference = "Stop"

. (Join-Path $PSScriptRoot "arcane-script-common.ps1")

$root = Split-Path -Parent $PSScriptRoot
$runtimeConfig = Resolve-ConfigPath `
    -Primary (Join-Path $root "config\ArcaneEDR.config") `
    -Example (Join-Path $root "config\ArcaneEDR.example.config")
if ([string]::IsNullOrWhiteSpace($ServiceName)) {
    $ServiceName = Get-ConfigValue -Path $runtimeConfig -Name "ServiceName" -Default "ArcaneEDR"
}

$svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($svc) {
    if ($svc.Status -ne "Stopped") {
        Stop-Service -Name $ServiceName -Force
        $svc.WaitForStatus("Stopped", "00:00:20")
    }
    sc.exe delete $ServiceName | Out-Host
    Write-Host "Deleted $ServiceName"
} else {
    Write-Host "Service $ServiceName is not installed."
}
