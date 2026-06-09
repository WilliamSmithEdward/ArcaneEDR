# Response Safety And Rollback

Arcane EDR must not take containment actions unless the operator made that
choice clearly and can recover from it.

The default is safe:

```ini
ResponseMode=AlertOnly
EnableFirewallBlockResponse=false
EnableProcessTerminationResponse=false
EnableResponsePolicy=true
```

With this default, Arcane logs alerts only. It does not add firewall rules and
does not terminate processes.

## Response Modes

| Mode | Action | Requires |
| --- | --- | --- |
| `AlertOnly` | No response action | Nothing |
| `DryRunBlockRemoteIp` | Logs the firewall rule it would create and any active-policy skip reason | Nothing |
| `DryRunTerminateProcess` | Logs the process it would terminate and any active-policy or target-eligibility skip reason | Nothing |
| `DryRunBlockAndTerminate` | Logs both intended actions and skip reasons | Nothing |
| `BlockRemoteIp` | Adds a Windows Firewall outbound block | `EnableFirewallBlockResponse=true` |
| `TerminateProcess` | Kills the target process | `EnableProcessTerminationResponse=true` |
| `BlockAndTerminate` | Adds firewall block and kills process | Both action gates |

Active modes also require `EnableResponseLedger=true`. Validation fails if an
active mode is configured without the required action gate or response ledger.

## Response Policy

Active response has a second safety layer:

```json
{
  "response_policy": {
    "allowed_rule_ids": [],
    "allowed_categories": [],
    "blocked_rule_ids": [
      "SERVICE-STARTED",
      "SERVICE-STOPPED",
      "SERVICE-RECOVERED-AFTER-UNCLEAN-STOP",
      "TEST-ALERT"
    ],
    "blocked_categories": [
      "Agent",
      "AI",
      "Baseline",
      "Health",
      "Response",
      "Test"
    ],
    "protected_process_names": [
      "System",
      "Idle",
      "Registry",
      "smss.exe",
      "csrss.exe",
      "wininit.exe",
      "winlogon.exe",
      "services.exe",
      "lsass.exe",
      "svchost.exe",
      "explorer.exe"
    ]
  }
}
```

When `EnableResponsePolicy=true`, active modes only act on alerts whose rule ID
or category appears in `response_policy.allowed_rule_ids` or
`response_policy.allowed_categories` in `PolicyFile`. The example policy leaves both allowlists empty,
so active response skips all actions until the operator explicitly allows a
rule or category.

`response_policy.blocked_rule_ids` and `response_policy.blocked_categories`
always win over allow entries. This keeps service-health, test, AI, baseline,
response-follow-up, and agent guardrail alerts from becoming containment
triggers by default.

Process termination also re-checks the live PID's process name before killing.
If the live process no longer matches the alert target, or the process is in
`response_policy.protected_process_names` or configured agent process/tool lists, Arcane
records a response-ledger skip instead of killing it.

## Recommended Test Path

Start with dry-run:

```ini
ResponseMode=DryRunBlockRemoteIp
ResponseMinimumScore=95
EnableFirewallBlockResponse=false
EnableProcessTerminationResponse=false
EnableResponseLedger=true
```

Review intended actions:

```powershell
Get-Content C:\Security\ArcaneResponseLedger.jsonl -Tail 20
.\bin\ArcaneEDR.exe --response-firewall list
```

Only enable active firewall blocking after dry-run behavior is understood.
Before switching to an active mode, add one narrow
`response_policy.allowed_rule_ids` entry for the rule you intend to test.
Process termination should remain disabled unless you are deliberately testing a
specific manual workflow.

## Firewall Rule Naming

Arcane-created firewall blocks use this exact prefix:

```text
ArcaneEDR_BLOCK_
```

Each block appends a GUID response ID:

```text
ArcaneEDR_BLOCK_<response-id>
```

The same `response_id` and `firewall_rule_name` are written to the response
ledger with the triggering rule ID, title, score, target type, and target value.
This makes every Arcane firewall block traceable back to the alert that caused
it.

## Firewall Rollback

List Arcane firewall response records:

```powershell
.\bin\ArcaneEDR.exe --response-firewall list
```

Remove one Arcane firewall rule by response ID or rule name:

```powershell
.\bin\ArcaneEDR.exe --response-firewall remove <response-id-or-ArcaneEDR_BLOCK_guid>
```

The remove command accepts only a 32-hex response ID, dashes optional, or an
exact `ArcaneEDR_BLOCK_<response-id>` rule name. Other firewall rule names are
rejected by the rollback helper.

Remove all Arcane-owned firewall block rules:

```powershell
.\bin\ArcaneEDR.exe --response-firewall remove-all
```

Emergency PowerShell equivalent:

```powershell
Get-NetFirewallRule -DisplayName 'ArcaneEDR_BLOCK_*' | Remove-NetFirewallRule
```

These commands only target rules with the `ArcaneEDR_BLOCK_` prefix.

## Process Termination

Process termination is different from firewall blocking. A killed process cannot
be truly rolled back. You may be able to restart an application, but Arcane
cannot undo lost process state, interrupted work, or side effects.

For that reason:

- `TerminateProcess` and `BlockAndTerminate` require
  `EnableProcessTerminationResponse=true`.
- Process termination should usually be tested in dry-run mode.
- If termination is used and a same-named process relaunches soon after, Arcane
  raises `RESPONSE-PROCESS-RESPAWN` as escalatory local evidence.

## Follow-Up And Notification Flood Protection

Response follow-up detections are local evidence by default:

```ini
EnableResponseFollowUpDetections=true
ResponseProcessRespawnWindowMinutes=10
ResponseProcessRespawnMinimumScore=94
ResponseFollowUpExternalAlertMinimumScore=95
```

`RESPONSE-PROCESS-RESPAWN` indicates that Arcane terminated a process and then
observed a same-named process launch inside the configured window. This can
mean service recovery, a supervisor process, persistence, or resilient malware.

The external notification threshold is intentionally separate so a respawn loop
does not flood email or webhook channels. Local logs, incident grouping, support
bundles, and response ledgers still preserve the evidence.

## Operator Rules

- Keep `ResponseMode=AlertOnly` for normal baseline and tuning.
- Prefer dry-run modes before active response.
- Enable firewall blocking and process termination separately.
- Do not enable process termination unless the rollback limitation is accepted.
- Confirm rollback commands work before relying on active firewall blocking.
