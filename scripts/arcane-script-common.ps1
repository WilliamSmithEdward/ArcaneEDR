$ErrorActionPreference = "Stop"

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

function Get-VersionFromSource {
    param([string]$Root)

    $versionFile = Join-Path $Root "src\VersionInfo.cs"
    foreach ($line in Get-Content -LiteralPath $versionFile) {
        if ($line -match 'public const string Version = "([^"]+)"') {
            return $Matches[1]
        }
    }

    throw "Could not read version from $versionFile."
}

function Set-ConfigValue {
    param(
        [string]$Path,
        [string]$Name,
        [string]$Value
    )

    $lines = New-Object "System.Collections.Generic.List[string]"
    $found = $false
    if (Test-Path -LiteralPath $Path) {
        foreach ($rawLine in Get-Content -LiteralPath $Path) {
            $line = $rawLine.Trim()
            if ($line.Length -gt 0 -and !$line.StartsWith("#")) {
                $equals = $line.IndexOf("=")
                if ($equals -gt 0) {
                    $key = $line.Substring(0, $equals).Trim()
                    if ($key.Equals($Name, [System.StringComparison]::OrdinalIgnoreCase)) {
                        $lines.Add($Name + "=" + $Value)
                        $found = $true
                        continue
                    }
                }
            }

            $lines.Add($rawLine)
        }
    }

    if (!$found) {
        $lines.Add($Name + "=" + $Value)
    }

    Set-Content -LiteralPath $Path -Value $lines -Encoding ASCII
}

function Set-ConfigLine {
    param(
        [System.Collections.Generic.List[string]]$Lines,
        [string]$Name,
        [string]$Value
    )

    $pattern = "^\s*" + [System.Text.RegularExpressions.Regex]::Escape($Name) + "\s*="
    for ($i = 0; $i -lt $Lines.Count; $i++) {
        if ($Lines[$i] -match $pattern) {
            $Lines[$i] = "$Name=$Value"
            return
        }
    }

    $Lines.Add("$Name=$Value")
}

function Test-IsAdministrator {
    $principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Test-SamePath {
    param(
        [string]$Left,
        [string]$Right
    )

    if ([string]::IsNullOrWhiteSpace($Left) -or [string]::IsNullOrWhiteSpace($Right)) {
        return $false
    }

    $leftFullPath = [System.IO.Path]::GetFullPath($Left).TrimEnd('\')
    $rightFullPath = [System.IO.Path]::GetFullPath($Right).TrimEnd('\')
    return $leftFullPath.Equals($rightFullPath, [System.StringComparison]::OrdinalIgnoreCase)
}

function Copy-FileIfDifferent {
    param(
        [string]$Source,
        [string]$Destination
    )

    if (!(Test-Path -LiteralPath $Source)) { return $false }
    if (Test-SamePath -Left $Source -Right $Destination) { return $true }

    Copy-Item -LiteralPath $Source -Destination $Destination -Force
    return $true
}

function Copy-IfExists {
    param(
        [string]$Source,
        [string]$Destination
    )

    if (Test-Path -LiteralPath $Source) {
        Copy-Item -LiteralPath $Source -Destination $Destination -Force
        return $true
    }

    return $false
}

function Copy-DirectoryContents {
    param(
        [string]$Source,
        [string]$Destination
    )

    if (!(Test-Path -LiteralPath $Source)) { return $false }
    if (Test-SamePath -Left $Source -Right $Destination) { return $true }

    New-Item -ItemType Directory -Force -Path $Destination | Out-Null
    Copy-Item -Path (Join-Path $Source "*") -Destination $Destination -Recurse -Force
    return $true
}

function Copy-DirectoryContentsIfExists {
    param(
        [string]$Source,
        [string]$Destination,
        [scriptblock]$Logger = $null
    )

    if (!(Test-Path -LiteralPath $Source)) { return $false }

    New-Item -ItemType Directory -Force -Path $Destination | Out-Null
    Copy-Item -Path (Join-Path $Source "*") -Destination $Destination -Recurse -Force
    Write-ArcaneScriptMessage -Message "Copied directory contents: $Source -> $Destination" -Logger $Logger
    return $true
}

function Test-PathContainsRoot {
    param(
        [string]$Value,
        [string]$RootPath
    )

    if ([string]::IsNullOrWhiteSpace($Value) -or [string]::IsNullOrWhiteSpace($RootPath)) {
        return $false
    }

    return $Value.IndexOf($RootPath, [System.StringComparison]::OrdinalIgnoreCase) -ge 0
}

function Write-ArcaneScriptMessage {
    param(
        [string]$Message,
        [scriptblock]$Logger = $null
    )

    if ($Logger) {
        & $Logger $Message
        return
    }

    Write-Host $Message
}

function Quote-Arg {
    param([string]$Value)

    return '"' + $Value.Replace('"', '\"') + '"'
}

function Clear-StaleAgentWorkspaceRoot {
    param(
        [string]$Path,
        [string]$SourceRoot,
        [scriptblock]$Logger = $null
    )

    if (!(Test-Path -LiteralPath $Path)) { return }

    $sourceRootFullPath = [System.IO.Path]::GetFullPath($SourceRoot).TrimEnd('\')
    $sourceParentFullPath = Split-Path -Parent $sourceRootFullPath
    $lines = Get-Content -LiteralPath $Path
    $changed = $false
    $updated = foreach ($line in $lines) {
        if ($line -match '^\s*AgentWorkspaceRoots\s*=') {
            $value = ($line -split '=', 2)[1].Trim()
            if ($value.Length -gt 0 -and
                ((Test-PathContainsRoot -Value $value -RootPath $sourceRootFullPath) -or
                 (Test-PathContainsRoot -Value $value -RootPath $sourceParentFullPath))) {
                $changed = $true
                'AgentWorkspaceRoots='
            }
            else {
                $line
            }
        }
        else {
            $line
        }
    }

    if (!$changed) { return }

    $backup = $Path + ".bak-machine-agnostic-" + (Get-Date -Format "yyyyMMdd-HHmmss")
    Copy-Item -LiteralPath $Path -Destination $backup -Force
    Set-Content -LiteralPath $Path -Value $updated -Encoding ASCII
    Write-ArcaneScriptMessage -Message "Cleared stale AgentWorkspaceRoots from $Path" -Logger $Logger
    Write-ArcaneScriptMessage -Message "Backed up config before machine-agnostic cleanup: $backup" -Logger $Logger
}
