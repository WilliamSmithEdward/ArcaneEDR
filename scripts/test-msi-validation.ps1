param(
    [string]$MsiPath = "",
    [switch]$RunSilentRepair,
    [switch]$RunAdminValidation,
    [switch]$RequireCodeSigning
)

$ErrorActionPreference = "Stop"

function Pass {
    param([string]$Message)
    Write-Host "[PASS] $Message"
}

function Warn {
    param([string]$Message)
    Write-Host "[WARN] $Message"
}

function Fail {
    param([string]$Message)
    Write-Host "[FAIL] $Message"
    $script:Failures++
}

function Resolve-LatestMsi {
    param([string]$Root)

    $artifacts = Join-Path $Root "artifacts"
    if (!(Test-Path -LiteralPath $artifacts)) {
        throw "Artifacts directory not found: $artifacts"
    }

    $msi = Get-ChildItem -LiteralPath $artifacts -Filter "ArcaneEDR-*.msi" |
        Sort-Object LastWriteTimeUtc -Descending |
        Select-Object -First 1
    if ($null -eq $msi) {
        throw "No ArcaneEDR MSI found under $artifacts. Run scripts\build-msi.cmd first."
    }

    return $msi.FullName
}

function Test-Checksum {
    param([string]$Path)

    $checksumPath = "$Path.sha256.txt"
    if (!(Test-Path -LiteralPath $checksumPath)) {
        Fail "Missing checksum: $checksumPath"
        return
    }

    $expected = ((Get-Content -LiteralPath $checksumPath -Raw).Trim() -split '\s+')[0]
    $actual = (Get-FileHash -Algorithm SHA256 -LiteralPath $Path).Hash
    if ($expected.Equals($actual, [System.StringComparison]::OrdinalIgnoreCase)) {
        Pass "Checksum matches for $(Split-Path -Leaf $Path)"
    }
    else {
        Fail "Checksum mismatch for $(Split-Path -Leaf $Path)"
    }
}

function Test-Signature {
    param([string]$Path)

    $signature = Get-AuthenticodeSignature -LiteralPath $Path
    if ($signature.Status -eq "Valid") {
        Pass "Signature valid: $(Split-Path -Leaf $Path)"
        return
    }

    if ($RequireCodeSigning) {
        Fail "Signature is not valid for $(Split-Path -Leaf $Path): $($signature.Status)"
    }
    else {
        Warn "Signature is not valid for $(Split-Path -Leaf $Path): $($signature.Status). Public release signing remains a v0.8/v1.0 gate."
    }
}

function Invoke-Process {
    param(
        [string]$FilePath,
        [string[]]$ArgumentList,
        [string]$Name
    )

    $process = Start-Process -FilePath $FilePath -ArgumentList $ArgumentList -Wait -PassThru -WindowStyle Hidden
    if ($process.ExitCode -eq 0) {
        Pass "$Name completed"
        return
    }

    Fail "$Name failed with exit code $($process.ExitCode)"
}

$script:Failures = 0
$root = Split-Path -Parent $PSScriptRoot
if ([System.String]::IsNullOrWhiteSpace($MsiPath)) {
    $MsiPath = Resolve-LatestMsi -Root $root
}
$MsiPath = [System.IO.Path]::GetFullPath($MsiPath)
$version = [System.IO.Path]::GetFileNameWithoutExtension($MsiPath) -replace '^ArcaneEDR-', ''
$zipPath = Join-Path $root "artifacts\ArcaneEDR-$version.zip"
$installedRoot = Join-Path $env:ProgramFiles "Arcane EDR"
$installedExe = Join-Path $installedRoot "bin\ArcaneEDR.exe"
$installedGui = Join-Path $installedRoot "gui\ArcaneEDR.Gui.exe"

Write-Host "Arcane EDR MSI validation"
Write-Host "MSI: $MsiPath"
Write-Host "Version: $version"
Write-Host ""

if (Test-Path -LiteralPath $MsiPath) { Pass "MSI exists" } else { Fail "MSI not found: $MsiPath" }
if (Test-Path -LiteralPath $zipPath) { Pass "ZIP exists: $zipPath" } else { Fail "ZIP not found: $zipPath" }
Test-Checksum -Path $MsiPath
if (Test-Path -LiteralPath $zipPath) { Test-Checksum -Path $zipPath }
Test-Signature -Path $MsiPath

if (Test-Path -LiteralPath $installedExe) {
    $versionOutput = & $installedExe --version
    if ($versionOutput -join "`n" -match [regex]::Escape($version)) {
        Pass "Installed service binary reports $version"
    }
    else {
        Warn "Installed service binary does not report $version. Installed output: $($versionOutput -join ' | ')"
    }
}
else {
    Warn "Installed service binary not found at $installedExe"
}

if (Test-Path -LiteralPath $installedGui) {
    Pass "Installed GUI exists: $installedGui"
    try {
        & (Join-Path $root "scripts\test-gui-payload.ps1") -Path (Join-Path $installedRoot "gui")
        Pass "Installed GUI payload is internally consistent"
    }
    catch {
        Fail "Installed GUI payload validation failed: $($_.Exception.Message)"
    }
}
else {
    Warn "Installed GUI not found at $installedGui"
}

$service = Get-Service -Name ArcaneEDR -ErrorAction SilentlyContinue
if ($null -eq $service) {
    Warn "ArcaneEDR service is not installed on this machine."
}
elseif ($service.Status -eq "Running") {
    Pass "ArcaneEDR service is running"
}
else {
    Warn "ArcaneEDR service status is $($service.Status)"
}

if ($RunAdminValidation) {
    Invoke-Process -FilePath (Join-Path $root "scripts\run-admin-task.cmd") -ArgumentList @("ValidateAdmin") -Name "Admin validation task"
}
else {
    Warn "Admin validation task not run. Use -RunAdminValidation after install or upgrade."
}

if ($RunSilentRepair) {
    $logPath = Join-Path $env:TEMP "ArcaneEDR-msi-repair-$version.log"
    Invoke-Process -FilePath "msiexec.exe" -ArgumentList @("/fa", "`"$MsiPath`"", "/qn", "/norestart", "/L*v", "`"$logPath`"") -Name "Silent MSI repair"
    if (Test-Path -LiteralPath $logPath) {
        Pass "Silent repair log written: $logPath"
    }
}
else {
    Warn "Silent repair not run. Use -RunSilentRepair from an elevated shell for repair validation."
}

Write-Host ""
Write-Host "Manual/disposable-VM gates still required for full v0.8 signoff:"
Write-Host "- clean install on a fresh Windows VM"
Write-Host "- upgrade from the previous public MSI"
Write-Host "- uninstall preserving config/logs"
Write-Host "- explicit purge behavior, if enabled in the tested installer"
Write-Host "- failed install rollback"
Write-Host "- failed upgrade rollback"
Write-Host "- silent install and silent uninstall"
Write-Host "- high DPI, high contrast, keyboard-only, and Narrator GUI pass"

if ($script:Failures -gt 0) {
    throw "$script:Failures MSI validation check(s) failed."
}

Pass "MSI validation checks completed."
