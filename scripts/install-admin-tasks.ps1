param(
    [string]$SourceRoot = "",
    [string]$PublishedRoot = "",
    [string]$LogDirectory = "C:\Security\AdminTasks",
    [string]$TaskPath = "\ArcaneEDR\",
    [string]$RunAsUser = ""
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

function Quote-Arg {
    param([string]$Value)
    return '"' + $Value.Replace('"', '\"') + '"'
}

if (!(Test-IsAdministrator)) {
    throw "Run this script from an elevated PowerShell session."
}

$scriptRoot = $PSScriptRoot
$repoRoot = Split-Path -Parent $scriptRoot
if ([string]::IsNullOrWhiteSpace($SourceRoot)) {
    $SourceRoot = $repoRoot
}
$SourceRoot = [System.IO.Path]::GetFullPath($SourceRoot)

$deploymentConfig = Resolve-ConfigPath `
    -Primary (Join-Path $SourceRoot "config\Deployment.config") `
    -Example (Join-Path $SourceRoot "config\Deployment.example.config")
if ([string]::IsNullOrWhiteSpace($PublishedRoot)) {
    $applicationName = Get-ConfigValue -Path $deploymentConfig -Name "ApplicationName" -Default "ArcaneEDR"
    $destinationRoot = Get-ConfigValue -Path $deploymentConfig -Name "DestinationRoot" -Default (Join-Path $env:ProgramData "ArcaneEDR")
    $PublishedRoot = Join-Path $destinationRoot $applicationName
}
$PublishedRoot = [System.IO.Path]::GetFullPath($PublishedRoot)

if ([string]::IsNullOrWhiteSpace($RunAsUser)) {
    $RunAsUser = [Security.Principal.WindowsIdentity]::GetCurrent().Name
}

$protectedRoot = Join-Path $env:ProgramData "ArcaneEDR\AdminTasks"
$runnerSource = Join-Path $scriptRoot "admin-task-runner.ps1"
$runnerDestination = Join-Path $protectedRoot "admin-task-runner.ps1"

New-Item -ItemType Directory -Force -Path $protectedRoot, $LogDirectory | Out-Null
Copy-Item -LiteralPath $runnerSource -Destination $runnerDestination -Force

icacls $protectedRoot /inheritance:r /grant:r "Administrators:(OI)(CI)F" "SYSTEM:(OI)(CI)F" "Users:(OI)(CI)RX" | Out-Host
icacls $LogDirectory /inheritance:r /grant:r "Administrators:(OI)(CI)M" "SYSTEM:(OI)(CI)M" "Users:(OI)(CI)RX" | Out-Host

$principal = New-ScheduledTaskPrincipal -UserId $RunAsUser -LogonType Interactive -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet `
    -AllowStartIfOnBatteries `
    -DontStopIfGoingOnBatteries `
    -MultipleInstances IgnoreNew `
    -ExecutionTimeLimit (New-TimeSpan -Minutes 30)

$taskNames = @("PublishRestart", "InstallService", "UninstallService", "InstallSysmon", "ValidateAdmin")
foreach ($taskName in $taskNames) {
    $arguments = "-NoProfile -ExecutionPolicy Bypass -File " + (Quote-Arg $runnerDestination) +
        " -TaskName $taskName" +
        " -SourceRoot " + (Quote-Arg $SourceRoot) +
        " -PublishedRoot " + (Quote-Arg $PublishedRoot) +
        " -LogDirectory " + (Quote-Arg $LogDirectory)

    $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument $arguments
    Register-ScheduledTask `
        -TaskPath $TaskPath `
        -TaskName $taskName `
        -Action $action `
        -Principal $principal `
        -Settings $settings `
        -Description "Arcane EDR constrained admin task: $taskName" `
        -Force | Out-Null

    Write-Host "Registered $TaskPath$taskName as $RunAsUser"
}

Write-Host "Protected runner: $runnerDestination"
Write-Host "Admin task logs: $LogDirectory"
