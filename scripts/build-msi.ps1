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

function Set-ConfigValue {
    param(
        [string]$Path,
        [string]$Name,
        [string]$Value
    )

    $lines = @()
    $found = $false
    if (Test-Path -LiteralPath $Path) {
        foreach ($rawLine in Get-Content -LiteralPath $Path) {
            $line = $rawLine.Trim()
            if ($line.Length -gt 0 -and !$line.StartsWith("#")) {
                $equals = $line.IndexOf("=")
                if ($equals -gt 0) {
                    $key = $line.Substring(0, $equals).Trim()
                    if ($key.Equals($Name, [System.StringComparison]::OrdinalIgnoreCase)) {
                        $lines += ($Name + "=" + $Value)
                        $found = $true
                        continue
                    }
                }
            }

            $lines += $rawLine
        }
    }

    if (!$found) {
        $lines += ($Name + "=" + $Value)
    }

    $lines | Set-Content -LiteralPath $Path -Encoding ASCII
}

function ConvertTo-XmlAttribute {
    param([string]$Value)

    return [System.Security.SecurityElement]::Escape($Value)
}

function New-DeterministicGuid {
    param([string]$Value)

    $md5 = [System.Security.Cryptography.MD5]::Create()
    try {
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($Value)
        $hash = $md5.ComputeHash($bytes)
        $guid = New-Object System.Guid (,$hash)
        return "{" + $guid.ToString().ToUpperInvariant() + "}"
    }
    finally {
        $md5.Dispose()
    }
}

function New-HarvestFragment {
    param(
        [string]$DirectoryId,
        [string]$SourceRoot,
        [string]$ComponentGroupId,
        [string]$OutputPath,
        [string[]]$SkipRelative = @()
    )

    $script:ArcaneHarvestComponentIndex = 0
    $script:ArcaneHarvestDirectoryIndex = 0
    $componentIds = New-Object System.Collections.Generic.List[string]
    $xml = New-Object System.Text.StringBuilder

    function Add-DirectoryContents {
        param(
            [string]$CurrentPath,
            [string]$Indent
        )

        foreach ($file in Get-ChildItem -LiteralPath $CurrentPath -File | Sort-Object Name) {
            $relative = $file.FullName.Substring($SourceRoot.Length).TrimStart('\')
            if ($SkipRelative | Where-Object { $relative.Equals($_, [System.StringComparison]::OrdinalIgnoreCase) }) {
                continue
            }

            $script:ArcaneHarvestComponentIndex++
            $componentId = $ComponentGroupId + "Component" + $script:ArcaneHarvestComponentIndex.ToString("0000")
            $fileId = $ComponentGroupId + "File" + $script:ArcaneHarvestComponentIndex.ToString("0000")
            $guid = New-DeterministicGuid -Value ($ComponentGroupId + "|" + $relative.ToLowerInvariant())
            $source = ConvertTo-XmlAttribute -Value $file.FullName
            [void]$componentIds.Add($componentId)
            [void]$xml.AppendLine("$Indent<Component Id=`"$componentId`" Guid=`"$guid`">")
            [void]$xml.AppendLine("$Indent  <File Id=`"$fileId`" Source=`"$source`" KeyPath=`"yes`" />")
            [void]$xml.AppendLine("$Indent</Component>")
        }

        foreach ($directory in Get-ChildItem -LiteralPath $CurrentPath -Directory | Sort-Object Name) {
            $script:ArcaneHarvestDirectoryIndex++
            $childDirectoryId = $ComponentGroupId + "Dir" + $script:ArcaneHarvestDirectoryIndex.ToString("0000")
            $name = ConvertTo-XmlAttribute -Value $directory.Name
            [void]$xml.AppendLine("$Indent<Directory Id=`"$childDirectoryId`" Name=`"$name`">")
            Add-DirectoryContents -CurrentPath $directory.FullName -Indent ($Indent + "  ")
            [void]$xml.AppendLine("$Indent</Directory>")
        }
    }

    [void]$xml.AppendLine('<?xml version="1.0" encoding="utf-8"?>')
    [void]$xml.AppendLine('<Wix xmlns="http://wixtoolset.org/schemas/v4/wxs">')
    [void]$xml.AppendLine('  <Fragment>')
    [void]$xml.AppendLine("    <DirectoryRef Id=`"$DirectoryId`">")
    Add-DirectoryContents -CurrentPath $SourceRoot -Indent "      "
    [void]$xml.AppendLine('    </DirectoryRef>')
    [void]$xml.AppendLine("    <ComponentGroup Id=`"$ComponentGroupId`">")
    foreach ($componentId in $componentIds) {
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
Copy-Item -LiteralPath (Join-Path $root "config\ArcaneEDR.example.config") -Destination (Join-Path $stage "config\ArcaneEDR.config") -Force
Copy-Item -LiteralPath (Join-Path $root "config\Deployment.example.config") -Destination (Join-Path $stage "config\Deployment.config") -Force
Copy-Item -LiteralPath (Join-Path $root "config\arcaneedr-sysmon.xml") -Destination (Join-Path $stage "config") -Force
Copy-Item -LiteralPath (Join-Path $root "config\custom-rules.json") -Destination (Join-Path $stage "config") -Force
Copy-Item -LiteralPath (Join-Path $root "config\arcane-policy.example.json") -Destination (Join-Path $stage "config") -Force

$programFiles = [Environment]::GetFolderPath([Environment+SpecialFolder]::ProgramFiles)
if ([string]::IsNullOrWhiteSpace($programFiles)) { $programFiles = "C:\Program Files" }
$programData = [Environment]::GetFolderPath([Environment+SpecialFolder]::CommonApplicationData)
if ([string]::IsNullOrWhiteSpace($programData)) { $programData = "C:\ProgramData" }
$dataRoot = Join-Path $programData "Arcane EDR"
Set-ConfigValue -Path (Join-Path $stage "config\ArcaneEDR.config") -Name "LogDirectory" -Value $dataRoot
Set-ConfigValue -Path (Join-Path $stage "config\ArcaneEDR.config") -Name "PolicyFile" -Value "arcane-policy.example.json"
Set-ConfigValue -Path (Join-Path $stage "config\Deployment.config") -Name "ApplicationName" -Value "Arcane EDR"
Set-ConfigValue -Path (Join-Path $stage "config\Deployment.config") -Name "DestinationRoot" -Value $programFiles
Set-ConfigValue -Path (Join-Path $stage "config\Deployment.config") -Name "ExecutableName" -Value "ArcaneEDR.exe"
Copy-Item -LiteralPath (Join-Path $root "README.md") -Destination $stage -Force
Copy-Item -LiteralPath (Join-Path $root "ROADMAP.md") -Destination $stage -Force
Copy-Item -LiteralPath (Join-Path $root "LICENSE") -Destination $stage -Force
Copy-Item -Path (Join-Path $root "docs\*.md") -Destination (Join-Path $stage "docs") -Force
Copy-Item -Path (Join-Path $root "scripts\*.ps1") -Destination (Join-Path $stage "scripts") -Force
Copy-Item -Path (Join-Path $root "scripts\*.cmd") -Destination (Join-Path $stage "scripts") -Force
Copy-Tree -Source (Join-Path $root "src\Assets") -Destination (Join-Path $stage "assets")

New-HarvestFragment -DirectoryId "GuiFolder" -SourceRoot $guiStage -ComponentGroupId "GuiFiles" -OutputPath (Join-Path $wixObj "GuiFiles.wxs")
New-HarvestFragment -DirectoryId "ConfigFolder" -SourceRoot (Join-Path $stage "config") -ComponentGroupId "ConfigFiles" -OutputPath (Join-Path $wixObj "ConfigFiles.wxs") -SkipRelative @("ArcaneEDR.config", "Deployment.config")
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
