param(
    [string]$Configuration = "Release"
)

$ErrorActionPreference = "Stop"

function Get-ConfigValue {
    param(
        [string]$Path,
        [string]$Name,
        [string]$Default
    )

    if (Test-Path $Path) {
        foreach ($rawLine in Get-Content -Path $Path) {
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

    if (Test-Path $Primary) { return $Primary }
    return $Example
}

$root = Split-Path -Parent $PSScriptRoot
$deploymentConfig = Resolve-ConfigPath `
    -Primary (Join-Path $root "config\Deployment.config") `
    -Example (Join-Path $root "config\Deployment.example.config")
$executableName = Get-ConfigValue -Path $deploymentConfig -Name "ExecutableName" -Default "ArcaneEDR.exe"
$srcRoot = Join-Path $root "src"
$sources = Get-ChildItem -Path $srcRoot -Recurse -Filter "*.cs" | Sort-Object FullName | ForEach-Object { $_.FullName }
$bin = Join-Path $root "bin"
$out = Join-Path $bin $executableName
$compiler = "$env:WINDIR\Microsoft.NET\Framework64\v4.0.30319\csc.exe"

if (!(Test-Path $compiler)) {
    $compiler = "$env:WINDIR\Microsoft.NET\Framework\v4.0.30319\csc.exe"
}

if (!(Test-Path $compiler)) {
    throw "Could not find .NET Framework csc.exe."
}

New-Item -ItemType Directory -Force -Path $bin | Out-Null

& $compiler /nologo /optimize+ /target:exe /out:$out `
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
