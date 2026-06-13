param(
    [string]$Version = "",
    [string]$OutputRoot = ""
)

$ErrorActionPreference = "Stop"

. (Join-Path $PSScriptRoot "arcane-script-common.ps1")

$root = Split-Path -Parent $PSScriptRoot
if ([string]::IsNullOrWhiteSpace($Version)) {
    $Version = Get-VersionFromSource -Root $root
}

if ([string]::IsNullOrWhiteSpace($OutputRoot)) {
    $OutputRoot = Join-Path $root "artifacts"
}

$deploymentConfig = Join-Path $root "config\Deployment.example.config"
$executableName = Get-ConfigValue -Path $deploymentConfig -Name "ExecutableName" -Default "ArcaneEDR.exe"
$packageName = "ArcaneEDR-$Version"
$stage = Join-Path $OutputRoot $packageName
$zip = Join-Path $OutputRoot "$packageName.zip"
$checksum = Join-Path $OutputRoot "$packageName.zip.sha256.txt"

New-Item -ItemType Directory -Force -Path $OutputRoot | Out-Null
if (Test-Path $stage) {
    Remove-Item -LiteralPath $stage -Recurse -Force
}
if (Test-Path $zip) {
    Remove-Item -LiteralPath $zip -Force
}
if (Test-Path $checksum) {
    Remove-Item -LiteralPath $checksum -Force
}

New-Item -ItemType Directory -Force -Path `
    (Join-Path $stage "bin"), `
    (Join-Path $stage "gui"), `
    (Join-Path $stage "config"), `
    (Join-Path $stage "scripts"), `
    (Join-Path $stage "docs"), `
    (Join-Path $stage "installer"), `
    (Join-Path $stage "src\Assets") | Out-Null

& (Join-Path $PSScriptRoot "build.ps1") -OutputPath (Join-Path $stage "bin\$executableName")
& (Join-Path $PSScriptRoot "build-gui.ps1") -OutputPath (Join-Path $stage "gui")
Copy-Item -LiteralPath (Join-Path $root "config\ArcaneEDR.example.config") -Destination (Join-Path $stage "config") -Force
Copy-Item -LiteralPath (Join-Path $root "config\Deployment.example.config") -Destination (Join-Path $stage "config") -Force
Copy-Item -LiteralPath (Join-Path $root "config\arcaneedr-sysmon.xml") -Destination (Join-Path $stage "config") -Force
Copy-Item -LiteralPath (Join-Path $root "config\custom-rules.json") -Destination (Join-Path $stage "config") -Force
Copy-Item -LiteralPath (Join-Path $root "config\arcane-policy.example.json") -Destination (Join-Path $stage "config") -Force
Copy-Item -Path (Join-Path $root "scripts\*.ps1") -Destination (Join-Path $stage "scripts") -Force
Copy-Item -Path (Join-Path $root "scripts\*.cmd") -Destination (Join-Path $stage "scripts") -Force
Copy-Item -Path (Join-Path $root "docs\*.md") -Destination (Join-Path $stage "docs") -Force
Copy-Item -Path (Join-Path $root "installer\*.wxs") -Destination (Join-Path $stage "installer") -Force
Copy-Item -Path (Join-Path $root "installer\*.rtf") -Destination (Join-Path $stage "installer") -Force
if (Test-Path (Join-Path $root "src\Assets")) {
    Copy-Item -Path (Join-Path $root "src\Assets\*") -Destination (Join-Path $stage "src\Assets") -Force
}
Copy-Item -LiteralPath (Join-Path $root "README.md") -Destination $stage -Force
Copy-Item -LiteralPath (Join-Path $root "ROADMAP.md") -Destination $stage -Force
Copy-Item -LiteralPath (Join-Path $root "LICENSE") -Destination $stage -Force

Compress-Archive -Path (Join-Path $stage "*") -DestinationPath $zip -Force

$hash = Get-FileHash -Path $zip -Algorithm SHA256
($hash.Hash.ToLowerInvariant() + "  " + (Split-Path -Leaf $zip)) | Set-Content -Path $checksum -Encoding ASCII

Write-Host "Release package: $zip"
Write-Host "SHA256 checksum: $checksum"
