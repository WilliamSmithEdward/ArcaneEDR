$ErrorActionPreference = "Stop"

$root = Split-Path -Parent $PSScriptRoot
$checkExe = Join-Path $root "bin\ArcaneEDR.check.exe"

function Fail-Test {
    param([string]$Message)
    throw $Message
}

function Invoke-Arcane {
    param([string[]]$Arguments)

    $output = & $checkExe @Arguments 2>&1
    $exit = $LASTEXITCODE
    if ($exit -ne 0) {
        $joined = ($output | Out-String).Trim()
        Fail-Test "ArcaneEDR.check.exe $($Arguments -join ' ') failed with exit code $exit. $joined"
    }

    return $output
}

function Assert-Contains {
    param(
        [object[]]$Output,
        [string]$Expected,
        [string]$Name
    )

    $text = ($Output | Out-String)
    if ($text.IndexOf($Expected, [System.StringComparison]::OrdinalIgnoreCase) -lt 0) {
        Fail-Test "$Name did not contain expected text: $Expected"
    }
}

function Assert-True {
    param(
        [bool]$Condition,
        [string]$Name
    )

    if (-not $Condition) {
        Fail-Test $Name
    }
}

& (Join-Path $PSScriptRoot "build.cmd") -OutputPath "bin\ArcaneEDR.check.exe"
if ($LASTEXITCODE -ne 0) {
    Fail-Test "Fixture build failed."
}

$version = Invoke-Arcane @("--version")
Assert-Contains $version "Arcane EDR" "Version output"

$validation = Invoke-Arcane @("--validate-config")
Assert-Contains $validation "Validation summary: 0 error(s)" "Config validation"

$policyJsonText = (Invoke-Arcane @("--policy-inspect", "--json") | Out-String).Trim()
$policy = $policyJsonText | ConvertFrom-Json
Assert-True ($policy.storage -eq "jsonl") "Policy inspect should declare JSONL storage."
Assert-True (($policy.scopes | Where-Object { $_.scope -eq "alert" }).rules -gt 0) "Policy inspect should include alert scoped rules."
Assert-True (($policy.scopes | Where-Object { $_.scope -eq "remote_endpoint" }).rules -gt 0) "Policy inspect should include remote endpoint scoped rules."
Assert-True (($policy.scopes | Where-Object { $_.scope -eq "response" }) -ne $null) "Policy inspect should include response scope."

$policyPreview = Invoke-Arcane @("--policy-preview", "--sample-rule", "NET-BEACON-TIMING-LOW-RISK", "--sample-process", "codex.exe", "--sample-score", "55")
Assert-Contains $policyPreview "Detection policy preview" "Policy preview"

$dailyPreview = Invoke-Arcane @("--preview-daily-report")
Assert-Contains $dailyPreview "Determination" "Daily report preview"

Write-Host "Fixture tests passed."
