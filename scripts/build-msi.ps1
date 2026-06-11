param(
    [string]$Version = "",
    [string]$OutputRoot = ""
)

$ErrorActionPreference = "Stop"

function Get-VersionFromSource {
    param([string]$Root)

    $versionFile = Join-Path $Root "src\VersionInfo.cs"
    foreach ($line in Get-Content -Path $versionFile) {
        if ($line -match 'public const string Version = "([^"]+)"') {
            return $Matches[1]
        }
    }

    throw "Could not read version from $versionFile."
}

function Copy-Tree {
    param(
        [string]$Source,
        [string]$Destination
    )

    if (!(Test-Path $Source)) { return }
    New-Item -ItemType Directory -Force -Path $Destination | Out-Null
    Copy-Item -Path (Join-Path $Source "*") -Destination $Destination -Recurse -Force
}

function New-HarvestFragment {
    param(
        [string]$DirectoryId,
        [string]$SourceRoot,
        [string]$ComponentGroupId,
        [string]$OutputPath,
        [string]$SkipRelative = ""
    )

    $files = Get-ChildItem -Path $SourceRoot -Recurse -File | Sort-Object FullName
    $componentIndex = 0
    $xml = New-Object System.Text.StringBuilder
    [void]$xml.AppendLine('<?xml version="1.0" encoding="utf-8"?>')
    [void]$xml.AppendLine('<Wix xmlns="http://wixtoolset.org/schemas/v4/wxs">')
    [void]$xml.AppendLine('  <Fragment>')
    [void]$xml.AppendLine("    <DirectoryRef Id=`"$DirectoryId`">")
    foreach ($file in $files) {
        $relative = $file.FullName.Substring($SourceRoot.Length).TrimStart('\')
        if (![string]::IsNullOrWhiteSpace($SkipRelative) -and
            $relative.Equals($SkipRelative, [System.StringComparison]::OrdinalIgnoreCase)) {
            continue
        }

        $componentIndex++
        $componentId = $ComponentGroupId + "Component" + $componentIndex.ToString("0000")
        $fileId = $ComponentGroupId + "File" + $componentIndex.ToString("0000")
        [void]$xml.AppendLine("      <Component Id=`"$componentId`" Guid=`"*`">")
        [void]$xml.AppendLine("        <File Id=`"$fileId`" Source=`"$($file.FullName)`" KeyPath=`"yes`" />")
        [void]$xml.AppendLine('      </Component>')
    }
    [void]$xml.AppendLine('    </DirectoryRef>')
    [void]$xml.AppendLine("    <ComponentGroup Id=`"$ComponentGroupId`">")
    for ($index = 1; $index -le $componentIndex; $index++) {
        $componentId = $ComponentGroupId + "Component" + $index.ToString("0000")
        [void]$xml.AppendLine("      <ComponentRef Id=`"$componentId`" />")
    }
    [void]$xml.AppendLine('    </ComponentGroup>')
    [void]$xml.AppendLine('  </Fragment>')
    [void]$xml.AppendLine('</Wix>')
    Set-Content -Path $OutputPath -Value $xml.ToString() -Encoding UTF8
}

$root = Split-Path -Parent $PSScriptRoot
if ([string]::IsNullOrWhiteSpace($Version)) {
    $Version = Get-VersionFromSource -Root $root
}

if ([string]::IsNullOrWhiteSpace($OutputRoot)) {
    $OutputRoot = Join-Path $root "artifacts"
}

$wix = "C:\Program Files\WiX Toolset v7.0\bin\wix.exe"
if (!(Test-Path $wix)) {
    $wix = "wix"
}

$stage = Join-Path $OutputRoot "msi-stage"
$wixObj = Join-Path $OutputRoot "wix"
$guiStage = Join-Path $stage "gui"
$msi = Join-Path $OutputRoot ("ArcaneEDR-" + $Version + ".msi")
$licenseRtf = Join-Path $root "installer\License.rtf"

if (Test-Path $stage) { Remove-Item -LiteralPath $stage -Recurse -Force }
if (Test-Path $wixObj) { Remove-Item -LiteralPath $wixObj -Recurse -Force }
New-Item -ItemType Directory -Force -Path `
    (Join-Path $stage "bin"), `
    $guiStage, `
    (Join-Path $stage "config"), `
    (Join-Path $stage "scripts"), `
    (Join-Path $stage "docs"), `
    (Join-Path $stage "assets"), `
    $wixObj | Out-Null

& (Join-Path $PSScriptRoot "build.ps1") -OutputPath (Join-Path $stage "bin\ArcaneEDR.exe")
& (Join-Path $PSScriptRoot "build-gui.ps1") -OutputPath $guiStage

Copy-Item -LiteralPath (Join-Path $root "config\ArcaneEDR.example.config") -Destination (Join-Path $stage "config") -Force
Copy-Item -LiteralPath (Join-Path $root "config\Deployment.example.config") -Destination (Join-Path $stage "config") -Force
Copy-Item -LiteralPath (Join-Path $root "config\arcaneedr-sysmon.xml") -Destination (Join-Path $stage "config") -Force
Copy-Item -LiteralPath (Join-Path $root "config\custom-rules.json") -Destination (Join-Path $stage "config") -Force
Copy-Item -LiteralPath (Join-Path $root "config\arcane-policy.example.json") -Destination (Join-Path $stage "config") -Force
Copy-Item -LiteralPath (Join-Path $root "README.md") -Destination $stage -Force
Copy-Item -LiteralPath (Join-Path $root "ROADMAP.md") -Destination $stage -Force
Copy-Item -LiteralPath (Join-Path $root "LICENSE") -Destination $stage -Force
Copy-Item -Path (Join-Path $root "docs\*.md") -Destination (Join-Path $stage "docs") -Force
Copy-Item -Path (Join-Path $root "scripts\*.ps1") -Destination (Join-Path $stage "scripts") -Force
Copy-Item -Path (Join-Path $root "scripts\*.cmd") -Destination (Join-Path $stage "scripts") -Force
Copy-Tree -Source (Join-Path $root "src\Assets") -Destination (Join-Path $stage "assets")

New-HarvestFragment -DirectoryId "GuiFolder" -SourceRoot $guiStage -ComponentGroupId "GuiFiles" -OutputPath (Join-Path $wixObj "GuiFiles.wxs")
New-HarvestFragment -DirectoryId "ConfigFolder" -SourceRoot (Join-Path $stage "config") -ComponentGroupId "ConfigFiles" -OutputPath (Join-Path $wixObj "ConfigFiles.wxs")
New-HarvestFragment -DirectoryId "ScriptsFolder" -SourceRoot (Join-Path $stage "scripts") -ComponentGroupId "ScriptFiles" -OutputPath (Join-Path $wixObj "ScriptFiles.wxs")
New-HarvestFragment -DirectoryId "DocsFolder" -SourceRoot (Join-Path $stage "docs") -ComponentGroupId "DocFiles" -OutputPath (Join-Path $wixObj "DocFiles.wxs")
New-HarvestFragment -DirectoryId "AssetsFolder" -SourceRoot (Join-Path $stage "assets") -ComponentGroupId "AssetFiles" -OutputPath (Join-Path $wixObj "AssetFiles.wxs")
New-HarvestFragment -DirectoryId "BinFolder" -SourceRoot (Join-Path $stage "bin") -ComponentGroupId "ServiceFiles" -OutputPath (Join-Path $wixObj "ServiceFiles.wxs") -SkipRelative "ArcaneEDR.exe"

if (Test-Path $msi) { Remove-Item -LiteralPath $msi -Force }

& $wix build `
    -acceptEula wix7 `
    -arch x64 `
    -d ProductVersion=$Version `
    -d StageRoot=$stage `
    -d GuiStage=$guiStage `
    -d LicenseRtf=$licenseRtf `
    -ext WixToolset.UI.wixext `
    -out $msi `
    (Join-Path $root "installer\Product.wxs") `
    (Join-Path $root "installer\Components.wxs") `
    (Join-Path $wixObj "ServiceFiles.wxs") `
    (Join-Path $wixObj "GuiFiles.wxs") `
    (Join-Path $wixObj "ConfigFiles.wxs") `
    (Join-Path $wixObj "ScriptFiles.wxs") `
    (Join-Path $wixObj "DocFiles.wxs") `
    (Join-Path $wixObj "AssetFiles.wxs")

if ($LASTEXITCODE -ne 0) {
    throw "MSI build failed with exit code $LASTEXITCODE."
}

$hash = Get-FileHash -Path $msi -Algorithm SHA256
($hash.Hash.ToLowerInvariant() + "  " + (Split-Path -Leaf $msi)) |
    Set-Content -Path ($msi + ".sha256.txt") -Encoding ASCII

Write-Host "MSI package: $msi"
Write-Host "SHA256 checksum: $msi.sha256.txt"
