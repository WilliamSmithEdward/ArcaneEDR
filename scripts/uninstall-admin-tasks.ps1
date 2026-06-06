param(
    [string]$TaskPath = "\ArcaneEDR\",
    [switch]$RemoveProtectedRunner
)

$ErrorActionPreference = "Stop"

$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (!$principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Run this script from an elevated PowerShell session."
}

$taskNames = @("PublishRestart", "InstallService", "UninstallService", "InstallSysmon", "ValidateAdmin")
foreach ($taskName in $taskNames) {
    $task = Get-ScheduledTask -TaskPath $TaskPath -TaskName $taskName -ErrorAction SilentlyContinue
    if ($task) {
        Unregister-ScheduledTask -TaskPath $TaskPath -TaskName $taskName -Confirm:$false
        Write-Host "Removed $TaskPath$taskName"
    }
}

if ($RemoveProtectedRunner) {
    $protectedRoot = Join-Path $env:ProgramData "ArcaneEDR\AdminTasks"
    if (Test-Path -LiteralPath $protectedRoot) {
        Remove-Item -LiteralPath $protectedRoot -Recurse -Force
        Write-Host "Removed $protectedRoot"
    }
}
