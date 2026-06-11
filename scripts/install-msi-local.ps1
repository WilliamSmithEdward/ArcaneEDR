param(
    [string]$MsiPath = "",
    [string]$InstallFolder = "",
    [string]$LogPath = "",
    [string]$ServiceName = "ArcaneEDR",
    [switch]$ReplaceExistingService,
    [switch]$Quiet
)

$ErrorActionPreference = "Stop"

function Test-IsAdministrator {
    $principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
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

function Get-ArcaneExecutableVersion {
    param([string]$Path)

    if (!(Test-Path -LiteralPath $Path)) { return "" }

    try {
        $output = & $Path --version 2>$null
        foreach ($line in $output) {
            if ($line -match 'Arcane EDR\s+([0-9]+\.[0-9]+\.[0-9]+)') {
                return $Matches[1]
            }
        }
    }
    catch {
        return ""
    }

    return ""
}

function Get-ServiceExecutablePath {
    param([string]$Name)

    $escapedName = $Name.Replace("'", "''")
    $service = Get-CimInstance -ClassName Win32_Service -Filter "Name='$escapedName'" -ErrorAction SilentlyContinue
    if (!$service -or [string]::IsNullOrWhiteSpace($service.PathName)) { return "" }

    $pathName = $service.PathName.Trim()
    if ($pathName.StartsWith('"')) {
        $endQuote = $pathName.IndexOf('"', 1)
        if ($endQuote -gt 1) {
            return $pathName.Substring(1, $endQuote - 1)
        }
    }

    $exeIndex = $pathName.IndexOf(".exe", [System.StringComparison]::OrdinalIgnoreCase)
    if ($exeIndex -ge 0) {
        return $pathName.Substring(0, $exeIndex + 4)
    }

    return $pathName
}

function Stop-ArcaneServiceIfRunning {
    param([string]$Name)

    $svc = Get-Service -Name $Name -ErrorAction SilentlyContinue
    if ($svc -and $svc.Status -ne "Stopped") {
        Write-Host "Stopping service $Name"
        Stop-Service -Name $Name -Force
        $svc.WaitForStatus("Stopped", "00:00:30")
    }
}

function Remove-ServiceRegistration {
    param([string]$Name)

    Stop-ArcaneServiceIfRunning -Name $Name
    $svc = Get-Service -Name $Name -ErrorAction SilentlyContinue
    if (!$svc) { return }

    Write-Host "Deleting existing service registration $Name"
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

function Write-InstalledDeploymentConfig {
    param(
        [string]$InstallFolder,
        [string]$DestinationRoot
    )

    $configDirectory = Join-Path $InstallFolder "config"
    New-Item -ItemType Directory -Force -Path $configDirectory | Out-Null

    @(
        "# Deployment-specific settings. Keep machine/user-specific install choices here.",
        "ApplicationName=Arcane EDR",
        ("DestinationRoot=" + $DestinationRoot.TrimEnd('\')),
        "ExecutableName=ArcaneEDR.exe",
        "SysmonExecutableName=Sysmon64.exe",
        "SysmonConfigFile=arcaneedr-sysmon.xml"
    ) | Set-Content -LiteralPath (Join-Path $configDirectory "Deployment.config") -Encoding ASCII
}

function Set-ConfigValue {
    param(
        [string]$Path,
        [string]$Name,
        [string]$Value
    )

    $lines = @()
    $found = $false
    if (Test-Path -LiteralPath $Path) {
        foreach ($rawLine in Get-Content -LiteralPath $Path) {
            $line = $rawLine.Trim()
            if ($line.Length -gt 0 -and !$line.StartsWith("#")) {
                $equals = $line.IndexOf("=")
                if ($equals -gt 0) {
                    $key = $line.Substring(0, $equals).Trim()
                    if ($key.Equals($Name, [System.StringComparison]::OrdinalIgnoreCase)) {
                        $lines += ($Name + "=" + $Value)
                        $found = $true
                        continue
                    }
                }
            }

            $lines += $rawLine
        }
    }

    if (!$found) {
        $lines += ($Name + "=" + $Value)
    }

    $lines | Set-Content -LiteralPath $Path -Encoding ASCII
}

function Write-InstalledRuntimeConfig {
    param(
        [string]$InstallFolder,
        [string]$DataRoot
    )

    $configDirectory = Join-Path $InstallFolder "config"
    New-Item -ItemType Directory -Force -Path $configDirectory | Out-Null

    $runtimeConfig = Join-Path $configDirectory "ArcaneEDR.config"
    if (Test-Path -LiteralPath $runtimeConfig) {
        return
    }

    $exampleConfig = Join-Path $configDirectory "ArcaneEDR.example.config"
    if (!(Test-Path -LiteralPath $exampleConfig)) {
        throw "ArcaneEDR.example.config was not found under installed config directory: $configDirectory"
    }

    Copy-Item -LiteralPath $exampleConfig -Destination $runtimeConfig -Force
    Set-ConfigValue -Path $runtimeConfig -Name "LogDirectory" -Value $DataRoot
    Set-ConfigValue -Path $runtimeConfig -Name "PolicyFile" -Value "arcane-policy.example.json"
}

$root = Split-Path -Parent $PSScriptRoot
$programFiles = [Environment]::GetFolderPath([Environment+SpecialFolder]::ProgramFiles)
if ([string]::IsNullOrWhiteSpace($programFiles)) {
    $programFiles = "C:\Program Files"
}
$programData = [Environment]::GetFolderPath([Environment+SpecialFolder]::CommonApplicationData)
if ([string]::IsNullOrWhiteSpace($programData)) {
    $programData = "C:\ProgramData"
}
$dataRoot = Join-Path $programData "Arcane EDR"

if ([string]::IsNullOrWhiteSpace($InstallFolder)) {
    $InstallFolder = Join-Path $programFiles "Arcane EDR"
}
if (!([System.IO.Path]::IsPathRooted($InstallFolder))) {
    throw "InstallFolder must be an absolute path: $InstallFolder"
}

if (!$(Test-IsAdministrator)) {
    $scriptPath = Join-Path $PSScriptRoot "install-msi-local.ps1"
    throw "Run this script from an elevated PowerShell session. Example: powershell.exe -NoProfile -ExecutionPolicy Bypass -File `"$scriptPath`" -ReplaceExistingService"
}

$resolvedMsi = Resolve-MsiPath -Root $root -RequestedPath $MsiPath
$targetVersion = Get-VersionFromSource -Root $root
$exe = Join-Path $InstallFolder "bin\ArcaneEDR.exe"

$existingServicePath = Get-ServiceExecutablePath -Name $ServiceName
if (![string]::IsNullOrWhiteSpace($existingServicePath) -and
    !$existingServicePath.Equals($exe, [System.StringComparison]::OrdinalIgnoreCase)) {
    if (!$ReplaceExistingService) {
        throw "Service $ServiceName points to '$existingServicePath'. Re-run with -ReplaceExistingService to remove that registration before installing to '$exe'."
    }

    Remove-ServiceRegistration -Name $ServiceName
}
else {
    Stop-ArcaneServiceIfRunning -Name $ServiceName
}

$stamp = Get-Date -Format "yyyyMMddHHmmss"
if ([string]::IsNullOrWhiteSpace($LogPath)) {
    $logRoot = "C:\Security\AdminTasks"
    New-Item -ItemType Directory -Force -Path $logRoot | Out-Null
    $LogPath = Join-Path $logRoot ("ArcaneEDR-msi-install-" + $stamp + ".log")
}
New-Item -ItemType Directory -Force -Path (Split-Path -Parent $LogPath) | Out-Null

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

if (!(Test-Path -LiteralPath $exe)) {
    throw "MSI completed but service executable was not found: $exe"
}

New-Item -ItemType Directory -Force -Path $dataRoot | Out-Null
Write-InstalledRuntimeConfig -InstallFolder $InstallFolder -DataRoot $dataRoot
Write-InstalledDeploymentConfig -InstallFolder $InstallFolder -DestinationRoot $programFiles

Write-Host ""
$versionOutput = & $exe --version
$versionOutput | ForEach-Object { Write-Host $_ }
if ($LASTEXITCODE -ne 0) {
    throw "Installed executable version check failed."
}

$installedVersion = Get-ArcaneExecutableVersion -Path $exe
if ($installedVersion -ne $targetVersion) {
    throw "Installed executable reports version '$installedVersion', expected '$targetVersion'. See $LogPath"
}

Write-Host ""
$serviceExecutable = Get-ServiceExecutablePath -Name $ServiceName
if (!$serviceExecutable.Equals($exe, [System.StringComparison]::OrdinalIgnoreCase)) {
    throw "Service $ServiceName points to '$serviceExecutable', expected '$exe'. See $LogPath"
}
Write-Host "Service executable: $serviceExecutable"

Write-Host ""
& $exe --validate-config
if ($LASTEXITCODE -ne 0) {
    throw "Installed executable config validation failed."
}

$svc = Get-Service -Name $ServiceName -ErrorAction Stop
if ($svc.Status -eq "Stopped") {
    Start-Service -Name $ServiceName
    $svc.WaitForStatus("Running", "00:00:30")
    $svc = Get-Service -Name $ServiceName -ErrorAction Stop
}

Write-Host ""
Write-Host "Service $ServiceName status: $($svc.Status)"
if ($process.ExitCode -eq 3010) {
    Write-Host "MSI completed and requested a reboot."
}
