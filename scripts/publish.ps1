param(
    [string]$ApplicationName = "",
    [string]$DestinationRoot = "",
    [switch]$OverwriteConfig,
    [switch]$OverwriteDeploymentConfig
)

$ErrorActionPreference = "Stop"

. (Join-Path $PSScriptRoot "arcane-script-common.ps1")


function Stop-ArcaneGuiIfRunning {
    param([string]$Destination)

    $guiExe = [System.IO.Path]::GetFullPath((Join-Path (Join-Path $Destination "gui") "ArcaneEDR.Gui.exe"))
    $candidates = Get-Process -Name "ArcaneEDR.Gui" -ErrorAction SilentlyContinue
    if (!$candidates) { return }

    $matches = @()
    foreach ($process in $candidates) {
        $path = ""
        try { $path = $process.Path } catch { $path = "" }
        if ([string]::IsNullOrWhiteSpace($path) -or
            [System.IO.Path]::GetFullPath($path).Equals($guiExe, [System.StringComparison]::OrdinalIgnoreCase)) {
            $matches += $process
        }
    }

    foreach ($process in $matches) {
        Write-Host "Closing Arcane GUI process $($process.Id)"
        try {
            if ($process.MainWindowHandle -ne 0) {
                [void]$process.CloseMainWindow()
            }
        }
        catch {
            Write-Host "GUI close request failed for process $($process.Id): $($_.Exception.Message)"
        }
    }

    $deadline = (Get-Date).AddSeconds(8)
    do {
        Start-Sleep -Milliseconds 250
        $remaining = @($matches | Where-Object {
            try { !$_.HasExited } catch { $false }
        })
    } while ($remaining.Count -gt 0 -and (Get-Date) -lt $deadline)

    foreach ($process in $remaining) {
        Write-Host "Force stopping Arcane GUI process $($process.Id)"
        Stop-Process -Id $process.Id -Force
    }
}

$root = Split-Path -Parent $PSScriptRoot
$deploymentConfig = Resolve-ConfigPath `
    -Primary (Join-Path $root "config\Deployment.config") `
    -Example (Join-Path $root "config\Deployment.example.config")
if ([string]::IsNullOrWhiteSpace($ApplicationName)) {
    $ApplicationName = Get-ConfigValue -Path $deploymentConfig -Name "ApplicationName" -Default "ArcaneEDR"
}
if ([string]::IsNullOrWhiteSpace($DestinationRoot)) {
    $DestinationRoot = Get-ConfigValue -Path $deploymentConfig -Name "DestinationRoot" -Default (Join-Path $env:ProgramData "ArcaneEDR")
}
$executableName = Get-ConfigValue -Path $deploymentConfig -Name "ExecutableName" -Default "ArcaneEDR.exe"
$destination = Join-Path $DestinationRoot $ApplicationName
$bin = Join-Path $destination "bin"
$gui = Join-Path $destination "gui"
$config = Join-Path $destination "config"
$scripts = Join-Path $destination "scripts"
$docs = Join-Path $destination "docs"
$tools = Join-Path $destination "tools"
$assets = Join-Path $destination "src\Assets"

Stop-ArcaneGuiIfRunning -Destination $destination

New-Item -ItemType Directory -Force -Path $bin, $gui, $config, $scripts, $docs, $tools, $assets | Out-Null

& (Join-Path $PSScriptRoot "build.ps1") -OutputPath (Join-Path $bin $executableName)
& (Join-Path $PSScriptRoot "build-gui.ps1") -OutputPath $gui
$sourceConfig = Join-Path $root "config\ArcaneEDR.config"
if (!(Test-Path $sourceConfig)) {
    $sourceConfig = Join-Path $root "config\ArcaneEDR.example.config"
}
$destinationConfig = Join-Path $config "ArcaneEDR.config"
if ($OverwriteConfig -or !(Test-Path $destinationConfig)) {
    Copy-Item -LiteralPath $sourceConfig -Destination $destinationConfig -Force
} else {
    Copy-Item -LiteralPath $sourceConfig -Destination (Join-Path $config "ArcaneEDR.example.config") -Force
    Write-Host "Preserved existing config: $destinationConfig"
    Write-Host "Wrote source config example: $(Join-Path $config "ArcaneEDR.example.config")"
}
Clear-StaleAgentWorkspaceRoot -Path $destinationConfig -SourceRoot $root
$sourceDeploymentConfig = $deploymentConfig
$destinationDeploymentConfig = Join-Path $config "Deployment.config"
if ($OverwriteDeploymentConfig -or !(Test-Path $destinationDeploymentConfig)) {
    Copy-Item -LiteralPath $sourceDeploymentConfig -Destination $destinationDeploymentConfig -Force
} else {
    Copy-Item -LiteralPath $sourceDeploymentConfig -Destination (Join-Path $config "Deployment.example.config") -Force
    Write-Host "Preserved existing deployment config: $destinationDeploymentConfig"
    Write-Host "Wrote source deployment config example: $(Join-Path $config "Deployment.example.config")"
}
Copy-Item -LiteralPath (Join-Path $root "config\arcaneedr-sysmon.xml") -Destination $config -Force
Copy-Item -LiteralPath (Join-Path $root "config\custom-rules.json") -Destination $config -Force
Copy-Item -LiteralPath (Join-Path $root "config\arcane-policy.example.json") -Destination $config -Force
Copy-Item -LiteralPath (Join-Path $root "README.md") -Destination $destination -Force
if (Test-Path (Join-Path $root "src\Assets")) {
    Copy-Item -Path (Join-Path $root "src\Assets\*") -Destination $assets -Force
}
Copy-Item -Path (Join-Path $root "docs\*.md") -Destination $docs -Force
Copy-Item -Path (Join-Path $root "scripts\*.ps1") -Destination $scripts -Force
Copy-Item -Path (Join-Path $root "scripts\*.cmd") -Destination $scripts -Force

Write-Host "Published to $destination"
Write-Host "Executable: $(Join-Path $bin $executableName)"
