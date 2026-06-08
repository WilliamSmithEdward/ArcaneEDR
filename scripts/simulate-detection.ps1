param(
    [ValidateSet("List", "EncodedPowerShell", "UnexpectedListener", "ScheduledTaskPersistence", "StartupFileDrop", "Demo", "All", "Cleanup")]
    [string]$Scenario = "List",

    [int]$DurationSeconds = 90,

    [int]$ListenerPort = 49291
)

$ErrorActionPreference = "Stop"

$TaskName = "\ArcaneEDRSimulation\ArcaneEdrSimulationTask"
$StartupSimulationFile = Join-Path ([Environment]::GetFolderPath("Startup")) "ArcaneEdrSimulation.cmd"

function Show-Scenarios {
    Write-Host "Arcane EDR safe detection simulations"
    Write-Host ""
    Write-Host "Scenarios:"
    Write-Host "  EncodedPowerShell        Runs a harmless encoded PowerShell command."
    Write-Host "  UnexpectedListener       Opens a localhost TCP listener for the selected duration."
    Write-Host "  ScheduledTaskPersistence Creates a harmless current-user scheduled task."
    Write-Host "  StartupFileDrop          Creates a harmless current-user Startup .cmd file."
    Write-Host "  Demo                     Runs a compact suspicious-activity demo with cleanup."
    Write-Host "  All                      Runs the listed detection scenarios."
    Write-Host "  Cleanup                  Removes scheduled-task and Startup-file simulation artifacts."
    Write-Host ""
    Write-Host "Examples:"
    Write-Host "  .\scripts\simulate-detection.cmd -Scenario EncodedPowerShell"
    Write-Host "  .\scripts\simulate-detection.cmd -Scenario UnexpectedListener -DurationSeconds 120 -ListenerPort 49291"
    Write-Host "  .\scripts\simulate-detection.cmd -Scenario ScheduledTaskPersistence"
    Write-Host "  .\scripts\simulate-detection.cmd -Scenario StartupFileDrop"
    Write-Host "  .\scripts\simulate-detection.cmd -Scenario Demo -DurationSeconds 120"
    Write-Host "  .\scripts\simulate-detection.cmd -Scenario Cleanup"
    Write-Host ""
    Write-Host "These simulations can generate real Arcane EDR alerts and external notifications if the service is running."
}

function Invoke-DemoSimulation {
    Write-Host "Running compact Arcane EDR demo path."
    Write-Host ""
    Write-Host "Step 1/3: remove prior simulation artifacts."
    Remove-ScheduledTaskSimulation
    Remove-StartupFileDropSimulation
    Write-Host ""
    Write-Host "Step 2/3: generate harmless suspicious process telemetry."
    Invoke-EncodedPowerShellSimulation
    Write-Host ""
    Write-Host "Step 3/3: open a localhost listener for $DurationSeconds second(s)."
    Write-Host "If the service is not running, run this in another shell while the listener is open:"
    Write-Host "  .\bin\ArcaneEDR.exe --poll-once"
    Invoke-UnexpectedListenerSimulation
    Write-Host ""
    Write-Host "Demo complete. Review local alerts with:"
    Write-Host "  .\bin\ArcaneEDR.exe --alert-volume --last 10m"
    Write-Host "  Get-Content .\bin\logs\ArcaneAlerts.jsonl -Tail 10"
}

function Invoke-EncodedPowerShellSimulation {
    $payload = "Write-Output 'Arcane EDR encoded PowerShell simulation'"
    $encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($payload))
    Write-Host "Running harmless encoded PowerShell simulation."
    & powershell.exe -NoProfile -EncodedCommand $encoded
    if ($LASTEXITCODE -ne 0) {
        throw "Encoded PowerShell simulation failed with exit code $LASTEXITCODE."
    }
}

function Invoke-UnexpectedListenerSimulation {
    if ($DurationSeconds -lt 5) {
        throw "DurationSeconds must be at least 5."
    }

    if ($ListenerPort -lt 1024 -or $ListenerPort -gt 65535) {
        throw "ListenerPort must be between 1024 and 65535."
    }

    $listener = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, $ListenerPort)
    Write-Host "Opening localhost TCP listener on port $ListenerPort for $DurationSeconds second(s)."
    $listener.Start()
    try {
        Start-Sleep -Seconds $DurationSeconds
    }
    finally {
        $listener.Stop()
        Write-Host "Listener stopped."
    }
}

function Invoke-ScheduledTaskPersistenceSimulation {
    $runAt = (Get-Date).AddMinutes(10).ToString("HH:mm")
    Write-Host "Creating harmless scheduled task $TaskName."
    & schtasks.exe /Create /TN $TaskName /SC ONCE /ST $runAt /TR "cmd.exe /c exit 0" /F | Write-Host
    if ($LASTEXITCODE -ne 0) {
        throw "Scheduled task simulation failed with exit code $LASTEXITCODE."
    }

    Write-Host "Scheduled task created. Run cleanup after Arcane EDR has had time to observe it:"
    Write-Host "  .\scripts\simulate-detection.cmd -Scenario Cleanup"
}

function Invoke-StartupFileDropSimulation {
    $startupFolder = Split-Path -Parent $StartupSimulationFile
    if (!(Test-Path $startupFolder)) {
        throw "Startup folder does not exist: $startupFolder"
    }

    Write-Host "Creating harmless Startup simulation file $StartupSimulationFile."
    Set-Content -Path $StartupSimulationFile -Encoding ASCII -Value @(
        "@echo off",
        "rem Arcane EDR Startup file-drop simulation",
        "exit /b 0"
    )

    Write-Host "Startup file created. Run cleanup after Arcane EDR has had time to observe it:"
    Write-Host "  .\scripts\simulate-detection.cmd -Scenario Cleanup"
}

function Remove-ScheduledTaskSimulation {
    Write-Host "Removing scheduled task $TaskName if it exists."
    & schtasks.exe /Delete /TN $TaskName /F | Write-Host
    if ($LASTEXITCODE -ne 0) {
        Write-Host "No scheduled-task simulation artifact was removed, or schtasks returned exit code $LASTEXITCODE."
    }
}

function Remove-StartupFileDropSimulation {
    if (Test-Path $StartupSimulationFile) {
        Write-Host "Removing Startup simulation file $StartupSimulationFile."
        Remove-Item -LiteralPath $StartupSimulationFile -Force
    }
    else {
        Write-Host "Startup simulation file was not present."
    }
}

if ($Scenario -eq "List") {
    Show-Scenarios
    exit 0
}

if ($Scenario -eq "Cleanup") {
    Remove-ScheduledTaskSimulation
    Remove-StartupFileDropSimulation
    exit 0
}

if ($Scenario -eq "Demo") {
    Invoke-DemoSimulation
    exit 0
}

if ($Scenario -eq "EncodedPowerShell" -or $Scenario -eq "All") {
    Invoke-EncodedPowerShellSimulation
}

if ($Scenario -eq "ScheduledTaskPersistence" -or $Scenario -eq "All") {
    Invoke-ScheduledTaskPersistenceSimulation
}

if ($Scenario -eq "StartupFileDrop" -or $Scenario -eq "All") {
    Invoke-StartupFileDropSimulation
}

if ($Scenario -eq "UnexpectedListener" -or $Scenario -eq "All") {
    Invoke-UnexpectedListenerSimulation
}
