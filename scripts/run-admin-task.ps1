param(
    [Parameter(Mandatory = $true)]
    [ValidateSet("PublishRestart", "InstallService", "UninstallService", "InstallSysmon", "ValidateAdmin")]
    [string]$TaskName,

    [string]$TaskPath = "\ArcaneEDR\",
    [string]$LogDirectory = "C:\Security\AdminTasks",
    [int]$TimeoutSeconds = 1800,
    [switch]$NoWait
)

$ErrorActionPreference = "Stop"

$task = Get-ScheduledTask -TaskPath $TaskPath -TaskName $TaskName -ErrorAction Stop
Start-ScheduledTask -TaskPath $TaskPath -TaskName $TaskName
Write-Host "Started $TaskPath$TaskName"

if ($NoWait) {
    return
}

$deadline = (Get-Date).AddSeconds($TimeoutSeconds)
do {
    Start-Sleep -Seconds 2
    $task = Get-ScheduledTask -TaskPath $TaskPath -TaskName $TaskName
    if ($task.State -ne "Running") {
        break
    }
} while ((Get-Date) -lt $deadline)

if ($task.State -eq "Running") {
    throw "Timed out waiting for $TaskPath$TaskName."
}

$info = Get-ScheduledTaskInfo -TaskPath $TaskPath -TaskName $TaskName
Write-Host "LastTaskResult: $($info.LastTaskResult)"

$logPath = Join-Path $LogDirectory "$TaskName.log"
if (Test-Path -LiteralPath $logPath) {
    Write-Host ""
    Write-Host "Last log lines from $logPath"
    Get-Content -LiteralPath $logPath -Tail 80
}

if ($info.LastTaskResult -ne 0) {
    exit $info.LastTaskResult
}
