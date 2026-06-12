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

$validationJsonText = (Invoke-Arcane @("--validate-config", "--json") | Out-String).Trim()
$validationJson = $validationJsonText | ConvertFrom-Json
Assert-True ($validationJson.schema -eq "arcane.validation.v1") "Validation JSON schema"
Assert-True ($validationJson.error_count -eq 0) "Validation JSON error count"
Assert-True ($validationJson.messages.Count -gt 0) "Validation JSON messages"

$healthJsonText = (Invoke-Arcane @("--health", "--json") | Out-String).Trim()
$healthJson = $healthJsonText | ConvertFrom-Json
Assert-True ($healthJson.schema -eq "arcane.health.v1") "Health JSON schema"
Assert-True (-not [System.String]::IsNullOrWhiteSpace($healthJson.service_state)) "Health JSON service state"

$policyJsonText = (Invoke-Arcane @("--policy-inspect", "--json") | Out-String).Trim()
$policy = $policyJsonText | ConvertFrom-Json
Assert-True ($policy.storage -eq "jsonl") "Policy inspect should declare JSONL storage."
Assert-True (($policy.scopes | Where-Object { $_.scope -eq "alert" }).rules -gt 0) "Policy inspect should include alert scoped rules."
Assert-True (($policy.scopes | Where-Object { $_.scope -eq "remote_endpoint" }).rules -gt 0) "Policy inspect should include remote endpoint scoped rules."
Assert-True (($policy.scopes | Where-Object { $_.scope -eq "response" }) -ne $null) "Policy inspect should include response scope."

$policyPreview = Invoke-Arcane @("--policy-preview", "--sample-rule", "NET-BEACON-TIMING-LOW-RISK", "--sample-process", "codex.exe", "--sample-score", "55")
Assert-Contains $policyPreview "Detection policy preview" "Policy preview"

$alertVolumeJson = (Invoke-Arcane @("--alert-volume", "--last", "10m", "--json") | Out-String).Trim() | ConvertFrom-Json
Assert-True ($alertVolumeJson.schema -eq "arcane.alert_volume.v1") "Alert volume JSON schema"

$agentActivityJson = (Invoke-Arcane @("--agent-activity", "--last", "10m", "--json") | Out-String).Trim() | ConvertFrom-Json
Assert-True ($agentActivityJson.schema -eq "arcane.agent_activity.v1") "Agent activity JSON schema"

$incidentsJson = (Invoke-Arcane @("--incidents", "--last", "10m", "--json") | Out-String).Trim() | ConvertFrom-Json
Assert-True ($incidentsJson.schema -eq "arcane.incidents.v1") "Incidents JSON schema"

$responseJson = (Invoke-Arcane @("--response-firewall", "list", "--json") | Out-String).Trim() | ConvertFrom-Json
Assert-True ($responseJson.schema -eq "arcane.response_firewall.v1") "Response firewall JSON schema"

$dailyPreview = Invoke-Arcane @("--preview-daily-report")
Assert-Contains $dailyPreview "Determination" "Daily report preview"
Assert-Contains $dailyPreview "Local machine" "Daily report host machine"
Assert-Contains $dailyPreview "Local IP addresses" "Daily report host IPs"

$dailyPreviewJson = (Invoke-Arcane @("--preview-daily-report", "--json") | Out-String).Trim() | ConvertFrom-Json
Assert-True (-not [System.String]::IsNullOrWhiteSpace($dailyPreviewJson.host_identity.machine_name)) "Daily report JSON host machine"
Assert-True ($null -ne $dailyPreviewJson.host_identity.local_ip_addresses) "Daily report JSON host IPs"

Write-Host "Fixture tests passed."
