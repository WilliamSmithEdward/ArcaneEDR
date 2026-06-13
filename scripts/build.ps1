param(
    [string]$Configuration = "Release",
    [string]$OutputPath = ""
)

$ErrorActionPreference = "Stop"

. (Join-Path $PSScriptRoot "arcane-script-common.ps1")

$root = Split-Path -Parent $PSScriptRoot
$deploymentConfig = Resolve-ConfigPath `
    -Primary (Join-Path $root "config\Deployment.config") `
    -Example (Join-Path $root "config\Deployment.example.config")
$executableName = Get-ConfigValue -Path $deploymentConfig -Name "ExecutableName" -Default "ArcaneEDR.exe"
$srcRoot = Join-Path $root "src"
$guiRoot = Join-Path $srcRoot "ArcaneEDR.Gui"
$sources = Get-ChildItem -Path $srcRoot -Recurse -Filter "*.cs" |
    Where-Object {
        !$_.FullName.StartsWith($guiRoot, [System.StringComparison]::OrdinalIgnoreCase) -and
        $_.FullName.IndexOf("\obj\", [System.StringComparison]::OrdinalIgnoreCase) -lt 0 -and
        $_.FullName.IndexOf("\bin\", [System.StringComparison]::OrdinalIgnoreCase) -lt 0
    } |
    Sort-Object FullName |
    ForEach-Object { $_.FullName }
$bin = Join-Path $root "bin"
$out = if ([System.String]::IsNullOrWhiteSpace($OutputPath)) {
    Join-Path $bin $executableName
} else {
    if ([System.IO.Path]::IsPathRooted($OutputPath)) {
        $OutputPath
    } else {
        Join-Path $root $OutputPath
    }
}
$compiler = "$env:WINDIR\Microsoft.NET\Framework64\v4.0.30319\csc.exe"
$icon = Join-Path $root "src\Assets\icon.ico"
$iconArgument = @()
if (Test-Path -LiteralPath $icon) {
    $iconArgument = @("/win32icon:$icon")
}

if (!(Test-Path $compiler)) {
    $compiler = "$env:WINDIR\Microsoft.NET\Framework\v4.0.30319\csc.exe"
}

if (!(Test-Path $compiler)) {
    throw "Could not find .NET Framework csc.exe."
}

New-Item -ItemType Directory -Force -Path (Split-Path -Parent $out) | Out-Null

& $compiler /nologo /optimize+ /target:exe /out:$out `
    $iconArgument `
    /reference:System.ServiceProcess.dll `
    /reference:System.Configuration.Install.dll `
    /reference:System.Management.dll `
    /reference:System.Core.dll `
    /reference:System.Xml.dll `
    /reference:System.Web.Extensions.dll `
    $sources

if ($LASTEXITCODE -ne 0) {
    throw "Build failed with compiler exit code $LASTEXITCODE."
}

Write-Host "Built $out"
