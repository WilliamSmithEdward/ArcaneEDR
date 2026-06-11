param(
    [string]$MsiPath = "",
    [string]$InstallFolder = "",
    [string]$LogPath = "",
    [string]$ServiceName = "",
    [switch]$MigrateLegacyService,
    [switch]$Quiet
)

$ErrorActionPreference = "Stop"

function Test-IsAdministrator {
    $principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-ConfigValue {
    param(
        [string]$Path,
        [string]$Name,
        [string]$Default
    )

    if (Test-Path -LiteralPath $Path) {
        foreach ($rawLine in Get-Content -LiteralPath $Path) {
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

    if (Test-Path -LiteralPath $Primary) { return $Primary }
    return $Example
}

function Get-VersionFromSource {
    param([string]$Root)

    $versionFile = Join-Path $Root "src\VersionInfo.cs"
    foreach ($line in Get-Content -LiteralPath $versionFile) {
        if ($line -match 'public const string Version = "([^"]+)"') {
            return $Matches[1]
        }
    }

    throw "Could not read version from $versionFile."
}

function Resolve-MsiPath {
    param(
        [string]$Root,
        [string]$RequestedPath
    )

    if (![string]::IsNullOrWhiteSpace($RequestedPath)) {
        $candidate = if ([System.IO.Path]::IsPathRooted($RequestedPath)) {
            $RequestedPath
        } else {
            Join-Path $Root $RequestedPath
        }
        if (!(Test-Path -LiteralPath $candidate)) {
            throw "MSI not found: $candidate"
        }
        return (Resolve-Path -LiteralPath $candidate).Path
    }

    $version = Get-VersionFromSource -Root $Root
    $versioned = Join-Path $Root ("artifacts\ArcaneEDR-" + $version + ".msi")
    if (Test-Path -LiteralPath $versioned) {
        return (Resolve-Path -LiteralPath $versioned).Path
    }

    $latest = Get-ChildItem -LiteralPath (Join-Path $Root "artifacts") -Filter "ArcaneEDR-*.msi" -ErrorAction SilentlyContinue |
        Sort-Object LastWriteTime -Descending |
        Select-Object -First 1
    if ($latest) { return $latest.FullName }

    throw "No Arcane EDR MSI was found under artifacts. Run scripts\build-msi.cmd first."
}

function Test-MsiProductRegistered {
    $uninstallRoots = @(
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall",
        "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
    )

    foreach ($root in $uninstallRoots) {
        if (!(Test-Path -LiteralPath $root)) { continue }
        foreach ($item in Get-ChildItem -LiteralPath $root -ErrorAction SilentlyContinue) {
            $displayName = (Get-ItemProperty -LiteralPath $item.PSPath -ErrorAction SilentlyContinue).DisplayName
            if ($displayName -eq "Arcane EDR") { return $true }
        }
    }

    return $false
}

function Remove-LegacyServiceRegistration {
    param([string]$Name)

    $svc = Get-Service -Name $Name -ErrorAction SilentlyContinue
    if (!$svc) {
        Write-Host "Service $Name is not currently installed."
        return
    }

    if ($svc.Status -ne "Stopped") {
        Write-Host "Stopping service $Name"
        Stop-Service -Name $Name -Force
        $svc.WaitForStatus("Stopped", "00:00:30")
    }

    Write-Host "Deleting legacy service registration $Name"
    sc.exe delete $Name | Out-Host

    $deadline = (Get-Date).AddSeconds(30)
    do {
        Start-Sleep -Seconds 1
        $svc = Get-Service -Name $Name -ErrorAction SilentlyContinue
    } while ($svc -and (Get-Date) -lt $deadline)

    if ($svc) {
        throw "Service $Name was deleted but is still visible. Reboot or wait for Windows service control manager cleanup before installing MSI."
    }
}

function Quote-MsiArgument {
    param([string]$Value)

    return '"' + $Value.Replace('"', '\"') + '"'
}

$root = Split-Path -Parent $PSScriptRoot
$deploymentConfig = Resolve-ConfigPath `
    -Primary (Join-Path $root "config\Deployment.config") `
    -Example (Join-Path $root "config\Deployment.example.config")

$applicationName = Get-ConfigValue -Path $deploymentConfig -Name "ApplicationName" -Default "ArcaneEDR"
$destinationRoot = Get-ConfigValue -Path $deploymentConfig -Name "DestinationRoot" -Default "C:\Applications"
if ([string]::IsNullOrWhiteSpace($InstallFolder)) {
    $InstallFolder = Join-Path $destinationRoot $applicationName
}

$installedRuntimeConfig = Join-Path $InstallFolder "config\ArcaneEDR.config"
$runtimeConfig = Resolve-ConfigPath `
    -Primary $installedRuntimeConfig `
    -Example (Resolve-ConfigPath `
        -Primary (Join-Path $root "config\ArcaneEDR.config") `
        -Example (Join-Path $root "config\ArcaneEDR.example.config"))

if ([string]::IsNullOrWhiteSpace($ServiceName)) {
    $ServiceName = Get-ConfigValue -Path $runtimeConfig -Name "ServiceName" -Default "ArcaneEDR"
}

if (!([System.IO.Path]::IsPathRooted($InstallFolder))) {
    throw "InstallFolder must be an absolute path: $InstallFolder"
}

if (!$(Test-IsAdministrator)) {
    $scriptPath = Join-Path $PSScriptRoot "install-msi-local.ps1"
    throw "Run this script from an elevated PowerShell session. Example: powershell.exe -NoProfile -ExecutionPolicy Bypass -File `"$scriptPath`" -MigrateLegacyService"
}

$resolvedMsi = Resolve-MsiPath -Root $root -RequestedPath $MsiPath

if ([string]::IsNullOrWhiteSpace($LogPath)) {
    $logRoot = "C:\Security\AdminTasks"
    New-Item -ItemType Directory -Force -Path $logRoot | Out-Null
    $stamp = Get-Date -Format "yyyyMMddHHmmss"
    $LogPath = Join-Path $logRoot ("ArcaneEDR-msi-install-" + $stamp + ".log")
}

New-Item -ItemType Directory -Force -Path (Split-Path -Parent $LogPath) | Out-Null

$existingService = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($existingService -and !(Test-MsiProductRegistered)) {
    if (!$MigrateLegacyService) {
        throw "Service $ServiceName exists but Arcane EDR is not registered as an MSI product. Re-run with -MigrateLegacyService to stop/delete only the legacy service registration before MSI install."
    }

    Remove-LegacyServiceRegistration -Name $ServiceName
}

$uiMode = if ($Quiet) { "/qn" } else { "/passive" }
$arguments = @(
    "/i",
    (Quote-MsiArgument $resolvedMsi),
    ("INSTALLFOLDER=" + (Quote-MsiArgument $InstallFolder)),
    "/norestart",
    "/l*v",
    (Quote-MsiArgument $LogPath),
    $uiMode
) -join " "

Write-Host "Installing MSI: $resolvedMsi"
Write-Host "Install folder: $InstallFolder"
Write-Host "MSI log: $LogPath"

$process = Start-Process -FilePath "msiexec.exe" -ArgumentList $arguments -Wait -PassThru
if ($process.ExitCode -ne 0 -and $process.ExitCode -ne 3010) {
    throw "MSI install failed with exit code $($process.ExitCode). See $LogPath"
}

$exe = Join-Path $InstallFolder "bin\ArcaneEDR.exe"
if (!(Test-Path -LiteralPath $exe)) {
    throw "MSI completed but service executable was not found: $exe"
}

Write-Host ""
& $exe --version
if ($LASTEXITCODE -ne 0) {
    throw "Installed executable version check failed."
}

Write-Host ""
& $exe --validate-config
if ($LASTEXITCODE -ne 0) {
    throw "Installed executable config validation failed."
}

$svc = Get-Service -Name $ServiceName -ErrorAction Stop
Write-Host ""
Write-Host "Service $ServiceName status: $($svc.Status)"
if ($process.ExitCode -eq 3010) {
    Write-Host "MSI completed and requested a reboot."
}
