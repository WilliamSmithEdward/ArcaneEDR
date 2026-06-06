param(
    [string]$ServiceName = ""
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
