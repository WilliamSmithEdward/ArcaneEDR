param(
    [Parameter(Mandatory = $true)]
    [ValidateSet("PublishRestart", "InstallService", "UninstallService", "InstallSysmon", "ValidateAdmin")]
    [string]$TaskName,

    [Parameter(Mandatory = $true)]
    [string]$SourceRoot,

    [Parameter(Mandatory = $true)]
    [string]$PublishedRoot,

    [Parameter(Mandatory = $true)]
    [string]$LogDirectory
)

$ErrorActionPreference = "Stop"

function Test-IsAdministrator {
    $principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Write-TaskLog {
    param([string]$Message)

    $line = "$(Get-Date -Format o) $Message"
    Write-Host $line
    Add-Content -LiteralPath $script:LogPath -Value $line -Encoding UTF8
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

function Get-RuntimeConfigPath {
    param([string]$Root)

    return Resolve-ConfigPath `
        -Primary (Join-Path $Root "config\ArcaneEDR.config") `
        -Example (Join-Path $Root "config\ArcaneEDR.example.config")
}

function Get-DeploymentConfigPath {
    param([string]$Root)

    return Resolve-ConfigPath `
        -Primary (Join-Path $Root "config\Deployment.config") `
        -Example (Join-Path $Root "config\Deployment.example.config")
}

function Get-ServiceName {
    $publishedRuntime = Get-RuntimeConfigPath -Root $PublishedRoot
    $sourceRuntime = Get-RuntimeConfigPath -Root $SourceRoot
    $configPath = if (Test-Path -LiteralPath $publishedRuntime) { $publishedRuntime } else { $sourceRuntime }
    return Get-ConfigValue -Path $configPath -Name "ServiceName" -Default "ArcaneEDR"
}

function Invoke-ArcaneBuild {
    $deploymentConfig = Get-DeploymentConfigPath -Root $SourceRoot
    $executableName = Get-ConfigValue -Path $deploymentConfig -Name "ExecutableName" -Default "ArcaneEDR.exe"
    $srcRoot = Join-Path $SourceRoot "src"
    $guiRoot = Join-Path $srcRoot "ArcaneEDR.Gui"
    $bin = Join-Path $SourceRoot "bin"
    $out = Join-Path $bin $executableName
    $icon = Join-Path $SourceRoot "src\Assets\icon.ico"
    $iconArgument = @()
    if (Test-Path -LiteralPath $icon) {
        $iconArgument = @("/win32icon:$icon")
    }
    $compiler = Join-Path $env:WINDIR "Microsoft.NET\Framework64\v4.0.30319\csc.exe"

    if (!(Test-Path -LiteralPath $compiler)) {
        $compiler = Join-Path $env:WINDIR "Microsoft.NET\Framework\v4.0.30319\csc.exe"
    }
    if (!(Test-Path -LiteralPath $compiler)) {
        throw "Could not find .NET Framework csc.exe."
    }

    New-Item -ItemType Directory -Force -Path $bin | Out-Null
    $sources = Get-ChildItem -LiteralPath $srcRoot -Recurse -Filter "*.cs" |
        Where-Object {
            !$_.FullName.StartsWith($guiRoot, [System.StringComparison]::OrdinalIgnoreCase) -and
            $_.FullName.IndexOf("\obj\", [System.StringComparison]::OrdinalIgnoreCase) -lt 0 -and
            $_.FullName.IndexOf("\bin\", [System.StringComparison]::OrdinalIgnoreCase) -lt 0
        } |
        Sort-Object FullName |
        ForEach-Object { $_.FullName }

    Write-TaskLog "Building $out"
    & $compiler /nologo /optimize+ /target:exe /out:$out `
        $iconArgument `
        /reference:System.ServiceProcess.dll `
        /reference:System.Configuration.Install.dll `
        /reference:System.Management.dll `
        /reference:System.Core.dll `
        /reference:System.Xml.dll `
        /reference:System.Web.Extensions.dll `
        $sources | ForEach-Object { Write-TaskLog $_ }

    if ($LASTEXITCODE -ne 0) {
        throw "Build failed with compiler exit code $LASTEXITCODE."
    }

    return $out
}

function Copy-IfExists {
    param(
        [string]$Source,
        [string]$Destination
    )

    if (Test-Path -LiteralPath $Source) {
        Copy-Item -LiteralPath $Source -Destination $Destination -Force
    }
}

function Publish-Arcane {
    $deploymentConfig = Get-DeploymentConfigPath -Root $SourceRoot
    $executableName = Get-ConfigValue -Path $deploymentConfig -Name "ExecutableName" -Default "ArcaneEDR.exe"
    $builtExe = Invoke-ArcaneBuild

    $bin = Join-Path $PublishedRoot "bin"
    $gui = Join-Path $PublishedRoot "gui"
    $config = Join-Path $PublishedRoot "config"
    $scripts = Join-Path $PublishedRoot "scripts"
    $docs = Join-Path $PublishedRoot "docs"
    $tools = Join-Path $PublishedRoot "tools"
    $assets = Join-Path $PublishedRoot "src\Assets"

    New-Item -ItemType Directory -Force -Path $bin, $gui, $config, $scripts, $docs, $tools, $assets | Out-Null
    Copy-Item -LiteralPath $builtExe -Destination (Join-Path $bin $executableName) -Force
    & (Join-Path (Join-Path $SourceRoot "scripts") "build-gui.ps1") -OutputPath $gui | ForEach-Object { Write-TaskLog $_ }
    if ($LASTEXITCODE -ne 0) {
        throw "GUI publish failed with exit code $LASTEXITCODE."
    }

    $sourceConfig = Join-Path $SourceRoot "config\ArcaneEDR.config"
    if (!(Test-Path -LiteralPath $sourceConfig)) {
        $sourceConfig = Join-Path $SourceRoot "config\ArcaneEDR.example.config"
    }
    $destinationConfig = Join-Path $config "ArcaneEDR.config"
    if (!(Test-Path -LiteralPath $destinationConfig)) {
        Copy-Item -LiteralPath $sourceConfig -Destination $destinationConfig -Force
    } else {
        Copy-Item -LiteralPath $sourceConfig -Destination (Join-Path $config "ArcaneEDR.example.config") -Force
        Write-TaskLog "Preserved existing config: $destinationConfig"
    }

    $destinationDeploymentConfig = Join-Path $config "Deployment.config"
    if (!(Test-Path -LiteralPath $destinationDeploymentConfig)) {
        Copy-Item -LiteralPath $deploymentConfig -Destination $destinationDeploymentConfig -Force
    } else {
        Copy-Item -LiteralPath $deploymentConfig -Destination (Join-Path $config "Deployment.example.config") -Force
        Write-TaskLog "Preserved existing deployment config: $destinationDeploymentConfig"
    }

    Copy-IfExists -Source (Join-Path $SourceRoot "config\arcaneedr-sysmon.xml") -Destination $config
    Copy-IfExists -Source (Join-Path $SourceRoot "config\custom-rules.json") -Destination $config
    Copy-IfExists -Source (Join-Path $SourceRoot "config\arcane-policy.example.json") -Destination $config
    Copy-IfExists -Source (Join-Path $SourceRoot "README.md") -Destination $PublishedRoot
    Copy-IfExists -Source (Join-Path $SourceRoot "ROADMAP.md") -Destination $PublishedRoot
    Copy-IfExists -Source (Join-Path $SourceRoot "LICENSE") -Destination $PublishedRoot
    if (Test-Path -LiteralPath (Join-Path $SourceRoot "src\Assets")) {
        Copy-Item -Path (Join-Path $SourceRoot "src\Assets\*") -Destination $assets -Force
    }
    Copy-Item -Path (Join-Path $SourceRoot "docs\*.md") -Destination $docs -Force
    Copy-Item -Path (Join-Path $SourceRoot "scripts\*.ps1") -Destination $scripts -Force
    Copy-Item -Path (Join-Path $SourceRoot "scripts\*.cmd") -Destination $scripts -Force

    Write-TaskLog "Published to $PublishedRoot"
}

function Stop-ArcaneServiceIfInstalled {
    $serviceName = Get-ServiceName
    $svc = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
    if ($svc -and $svc.Status -ne "Stopped") {
        Write-TaskLog "Stopping service $serviceName"
        Stop-Service -Name $serviceName -Force
        $svc.WaitForStatus("Stopped", "00:00:30")
    }
}

function Start-ArcaneServiceIfInstalled {
    $serviceName = Get-ServiceName
    $svc = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
    if ($svc) {
        Write-TaskLog "Starting service $serviceName"
        Start-Service -Name $serviceName
    }
}

function Invoke-PublishRestart {
    Stop-ArcaneServiceIfInstalled
    Publish-Arcane
    Start-ArcaneServiceIfInstalled
}

function Invoke-InstallService {
    Publish-Arcane

    $runtimeConfig = Get-RuntimeConfigPath -Root $PublishedRoot
    $deploymentConfig = Get-DeploymentConfigPath -Root $PublishedRoot
    $serviceName = Get-ConfigValue -Path $runtimeConfig -Name "ServiceName" -Default "ArcaneEDR"
    $displayName = Get-ConfigValue -Path $runtimeConfig -Name "ServiceDisplayName" -Default $serviceName
    $description = Get-ConfigValue -Path $runtimeConfig -Name "ServiceDescription" -Default "Monitors host, process, persistence, PowerShell, Sysmon, and network activity for suspicious behavior on unattended agent workstations."
    $executableName = Get-ConfigValue -Path $deploymentConfig -Name "ExecutableName" -Default "ArcaneEDR.exe"
    $exe = Join-Path (Join-Path $PublishedRoot "bin") $executableName

    if (Get-Service -Name $serviceName -ErrorAction SilentlyContinue) {
        throw "Service '$serviceName' already exists."
    }

    Write-TaskLog "Installing service $serviceName from $exe"
    New-Service -Name $serviceName `
        -BinaryPathName "`"$exe`"" `
        -DisplayName $displayName `
        -Description $description `
        -StartupType Automatic | Out-Null

    sc.exe failure $serviceName reset= 86400 actions= restart/60000/restart/60000/restart/300000 | ForEach-Object { Write-TaskLog $_ }
    sc.exe failureflag $serviceName 1 | ForEach-Object { Write-TaskLog $_ }
    Start-Service -Name $serviceName
    Write-TaskLog "Installed and started $serviceName"
}

function Invoke-UninstallService {
    $serviceName = Get-ServiceName
    $svc = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
    if (!$svc) {
        Write-TaskLog "Service $serviceName is not installed."
        return
    }

    if ($svc.Status -ne "Stopped") {
        Write-TaskLog "Stopping service $serviceName"
        Stop-Service -Name $serviceName -Force
        $svc.WaitForStatus("Stopped", "00:00:30")
    }

    sc.exe delete $serviceName | ForEach-Object { Write-TaskLog $_ }
    Write-TaskLog "Deleted $serviceName"
}

function Invoke-InstallSysmon {
    $deploymentConfig = Get-DeploymentConfigPath -Root $PublishedRoot
    $sysmonExecutableName = Get-ConfigValue -Path $deploymentConfig -Name "SysmonExecutableName" -Default "Sysmon64.exe"
    $sysmonConfigFile = Get-ConfigValue -Path $deploymentConfig -Name "SysmonConfigFile" -Default "arcaneedr-sysmon.xml"
    $sysmonExe = Join-Path (Join-Path $PublishedRoot "tools") $sysmonExecutableName
    $configPath = Join-Path (Join-Path $PublishedRoot "config") $sysmonConfigFile

    if (!(Test-Path -LiteralPath $sysmonExe)) {
        throw "Sysmon executable not found at '$sysmonExe'."
    }
    if (!(Test-Path -LiteralPath $configPath)) {
        throw "Sysmon config not found at '$configPath'."
    }

    Write-TaskLog "Installing Sysmon from $sysmonExe with $configPath"
    & $sysmonExe -accepteula -i $configPath | ForEach-Object { Write-TaskLog $_ }
    if ($LASTEXITCODE -ne 0) {
        throw "Sysmon install failed with exit code $LASTEXITCODE."
    }
}

function Invoke-ValidateAdmin {
    $deploymentConfig = Get-DeploymentConfigPath -Root $PublishedRoot
    $executableName = Get-ConfigValue -Path $deploymentConfig -Name "ExecutableName" -Default "ArcaneEDR.exe"
    $exe = Join-Path (Join-Path $PublishedRoot "bin") $executableName
    if (!(Test-Path -LiteralPath $exe)) {
        $deploymentConfig = Get-DeploymentConfigPath -Root $SourceRoot
        $executableName = Get-ConfigValue -Path $deploymentConfig -Name "ExecutableName" -Default "ArcaneEDR.exe"
        $exe = Join-Path (Join-Path $SourceRoot "bin") $executableName
    }
    if (!(Test-Path -LiteralPath $exe)) {
        $exe = Invoke-ArcaneBuild
    }

    Write-TaskLog "Running admin validation via $exe"
    & $exe --validate-config | ForEach-Object { Write-TaskLog $_ }
    if ($LASTEXITCODE -ne 0) {
        throw "Validation failed with exit code $LASTEXITCODE."
    }
}

New-Item -ItemType Directory -Force -Path $LogDirectory | Out-Null
$script:LogPath = Join-Path $LogDirectory ("$TaskName.log")

try {
    if (!(Test-IsAdministrator)) {
        throw "Admin task runner is not elevated."
    }

    Write-TaskLog "START $TaskName SourceRoot=$SourceRoot PublishedRoot=$PublishedRoot"
    switch ($TaskName) {
        "PublishRestart" { Invoke-PublishRestart }
        "InstallService" { Invoke-InstallService }
        "UninstallService" { Invoke-UninstallService }
        "InstallSysmon" { Invoke-InstallSysmon }
        "ValidateAdmin" { Invoke-ValidateAdmin }
        default { throw "Unsupported task: $TaskName" }
    }
    Write-TaskLog "SUCCESS $TaskName"
    exit 0
}
catch {
    Write-TaskLog ("ERROR " + $_.Exception.Message)
    exit 1
}
