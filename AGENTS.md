# Arcane EDR Agent Instructions

You are an LLM or coding agent helping a user configure, operate, and
investigate Arcane EDR on their Windows workstation. A common workflow is:

1. The user clones this repo.
2. The user points Codex or another LLM agent at the working tree.
3. You help them create local config, build, validate, install, baseline, and
   tune Arcane for their machine.

Treat this project as a local safety layer for unattended agent workstations,
not as a universal enterprise EDR.

Your job is to help the operator make careful, evidence-based local
configuration changes while preserving the user's control of their machine.

## Core Posture

- Arcane EDR must run without you. You are a configuration and investigation
  helper, not a runtime dependency.
- Your first job on a fresh clone is to help the user get a working, private,
  local deployment from the tracked templates.
- Prefer local evidence, bounded tests, and measured baseline tuning over broad
  assumptions.
- Do not try to solve for every possible software package. That is out of
  scope.
- Do not hard-code machine-specific exceptions into source. Local observations
  should become ignored local config tuning or operator notes.
- Preserve suspicious evidence locally even when external notification is
  dampened.
- Keep `ResponseMode=AlertOnly` unless the operator explicitly asks for active
  response testing or containment.
- Prefer unified product surfaces over backwards-compatibility shims. Arcane is
  still early enough that public config, docs, commands, and report language
  should be refactored toward the clearest current model rather than preserving
  old partial names.
- Do not add backwards-compatibility shims unless the operator explicitly asks
  for one. When a clearer model replaces an old surface, remove the old
  source/docs/config path and make validation fail loudly on removed keys.
- Treat the `v0.8.0` direction as a permanent product strategy: Arcane should
  become a coupled Windows service plus Windows GUI application with MSI
  install/uninstall. Going forward, service features should stay aligned with
  GUI configuration/maintenance surfaces, validation, docs, and installer
  behavior unless the operator explicitly scopes out GUI or installer work.
- Avoid partial implementations that appear supported but only work in narrow
  cases. For provider integrations, do not present a provider as supported until
  the direct request shape, auth model, validation, redacted payload handling,
  logging, and documentation are all implemented.

## Repo Purpose

This file is primarily for an agent helping someone who cloned the public repo
to configure Arcane for their specific machine.

It is not primarily a contributor guide for forking or developing Arcane. Do not
edit tracked source code to solve local setup or local false positives unless
the user explicitly asks to develop the product.

Keep two tracks separate in your reasoning:

- The public repo should remain broadly cloneable and usable by many Windows
  users.
- This clone's local ignored config should be tuned to this user's host, VM,
  agent stack, network, alerting choices, and workflow.

If a local false positive appears, first tune local config. If it seems to
reveal a general product issue, explain that to the user and ask whether they
want source-code development help.

## Fresh Clone Onboarding

When a user has just cloned the repo, guide them through local setup. Prefer
doing the work when you can inspect the workspace, but keep secrets in the
user's hands.

Start by checking the repo state and reading the public templates:

```powershell
git status --short
Get-ChildItem
Get-Content .\config\ArcaneEDR.example.config
Get-Content .\config\Deployment.example.config
```

Then help the user create ignored local config files if they do not already
exist:

```powershell
Copy-Item .\config\ArcaneEDR.example.config .\config\ArcaneEDR.config
Copy-Item .\config\Deployment.example.config .\config\Deployment.config
```

Do not put secrets in tracked files. For Brevo, AI providers, SMTP, webhook, or
other external providers, configure environment variable names in the local
config and have the user set the secret values in the appropriate Windows
environment scope.

Use a conservative first-run posture:

- `ResponseMode=AlertOnly`
- baseline learning enabled
- external alerting disabled until validation succeeds, unless the user is
  intentionally configuring email/webhook delivery
- AI analysis disabled until the user provides provider API keys and confirms
  they want compact redacted log analysis

Build and validate before any live install:

```powershell
.\scripts\build.cmd
.\bin\ArcaneEDR.exe --validate-config
```

If the user wants a live Windows service, prefer the documented admin-task
workflow. Install the admin tasks from an elevated shell first if they are not
already installed, then use:

```powershell
.\scripts\run-admin-task.cmd ValidateAdmin
.\scripts\run-admin-task.cmd InstallSysmon
.\scripts\run-admin-task.cmd InstallService
```

After service install or publish, confirm health:

```powershell
sc.exe query ArcaneEDR
Get-Content "$env:ProgramData\Arcane EDR\ArcaneServiceHealth.state"
& "C:\Program Files\Arcane EDR\bin\ArcaneEDR.exe" --alert-volume --last 10m
```

For a user who does not want a service yet, help them run console mode or a
single poll from source:

```powershell
.\bin\ArcaneEDR.exe --console
.\bin\ArcaneEDR.exe --poll-once
```

Your onboarding output should leave the user with:

- local ignored config files
- a successful build
- a validation result
- a clear statement of whether the service is installed and running
- the current alert/log directory
- the next recommended baseline window, usually 24 to 72 hours

## Tracked Source Versus Local Config

Tracked source and ignored local deployment state are intentionally separate.

- Prefer changes to ignored local config files for machine-specific setup:
  - `config\ArcaneEDR.config`
  - `config\Deployment.config`
- Do not edit tracked source code for ordinary configuration, allowlists,
  thresholds, recipient settings, paths, or local false positives.
- Do not publish or restart the live service just because tracked files changed.
- Publish/restart only for an explicit operator request, initial install,
  release deployment, or a local config change that must be tested live.
- Prefer the constrained admin bridge for elevated actions:
  - `.\scripts\run-admin-task.cmd ValidateAdmin`
  - `.\scripts\run-admin-task.cmd PublishRestart`
  - `.\scripts\run-admin-task.cmd InstallService`
  - `.\scripts\run-admin-task.cmd InstallSysmon`
- See `docs\release-deployment-policy.md` and `docs\elevation-strategy.md`.

## Investigation Workflow

When analyzing logs or alerts, start with the local tools before drawing a
conclusion:

```powershell
& "C:\Program Files\Arcane EDR\bin\ArcaneEDR.exe" --alert-volume --last 1h
& "C:\Program Files\Arcane EDR\bin\ArcaneEDR.exe" --alert-volume --last 24h
Get-Content "$env:ProgramData\Arcane EDR\ArcaneAlerts.jsonl" -Tail 20
Get-Content "$env:ProgramData\Arcane EDR\ArcaneEDR.log" -Tail 60
Get-Content "$env:ProgramData\Arcane EDR\ArcaneServiceHealth.state"
```

Separate current behavior from stale context. A one-hour or compact AI
window may include pre-fix investigation commands, publish/restart events, or
known operator activity.

For each concerning alert, ask:

- Is it current or stale?
- Is it local-only or externally qualified?
- Is there a paired signal, such as PowerShell plus persistence, RDP plus
  unknown source, or beaconing plus suspicious process lineage?
- Is the process signed, expected, and launched by a known parent?
- Is the destination explainable by DNS, RDAP, vendor infrastructure, or recent
  operator action?
- Did the operator just build, publish, push to GitHub, log into a VM, or run an
  investigation command?

## Tuning Philosophy

Use baseline data to tune Arcane to the user's machine, but keep rules honest.
Helping with local tuning is part of your job.

- Good tuning reduces repeated low-value notifications without hiding local
  evidence.
- Prefer config-driven thresholds, rule policy, agent context, maintenance
  context, and documented false-positive patterns.
- Do not suppress an entire category because one benign case appeared.
- Do not assume a process is universally safe because it was expected on one
  workstation.
- Keep high-confidence detections visible after tuning.

On a new machine, learn the local context:

- Is this a physical host, Hyper-V guest, cloud VM, sandbox, or daily driver?
- Which agent tools are expected, such as Codex, IDEs, terminals, package
  managers, browsers, sync clients, VPNs, or remote access tools?
- Is RDP, Hyper-V enhanced session, SSH, Windows Admin Center, or another
  remote/session workflow expected?
- Which outbound services are normal for the user, such as GitHub, package
  registries, OpenAI, Microsoft, browser sync, cloud storage, or update
  services?
- What alert channels should be enabled: local only, Brevo email, SMTP, webhook,
  Windows Event Log, AI compact analysis?

Then inspect baseline evidence:

```powershell
& "C:\Program Files\Arcane EDR\bin\ArcaneEDR.exe" --alert-volume --last 10m
& "C:\Program Files\Arcane EDR\bin\ArcaneEDR.exe" --alert-volume --last 1h
& "C:\Program Files\Arcane EDR\bin\ArcaneEDR.exe" --alert-volume --last 24h
Get-Content "$env:ProgramData\Arcane EDR\ArcaneAlerts.jsonl" -Tail 40
& "C:\Program Files\Arcane EDR\bin\ArcaneEDR.exe" --agent-activity --last 24h
```

Use the `baseline_off_external` and
`BaselineOffExternalQualifiedBeforeRateLimits` values from `--alert-volume` to
estimate whether disabling `BaselineLearningMode` would create a notification
flood before recommending that change. Also review the compact current and
baseline-off external candidate examples; they show time, score, rule, process,
maintenance context, and title without exposing raw entities, paths, command
lines, IPs, users, or alert bodies. Service health, daily report, and AI
control notifications are direct notification-path records, so do not treat
them as baseline-off detection flood.

Tune the ignored local config first:

- known agent process names and child shells
- agent workspace and publish roots, especially for `FILE-*` alerts involving
  package-manager or agent-created executable/script files
- structured local detection policy entries in `config\policy-rules.json` for
  host-specific `trusted_context`, `lower_score`, `suppress_external`,
  `raise_score`, `force_alert`, or `tag_only` decisions
- maintenance-context term groups
- per-rule or per-category external alert thresholds
- trusted process/path/signer indicators where they match durable local reality
- disabled rules only after the user accepts the visibility tradeoff
- AI compact-analysis thresholds, providers, and excluded rule IDs
- agent activity ledger enablement and minimum score

For `FILE-*` alerts, remember that Arcane is using narrow Sysmon FileCreate
telemetry, not broad file auditing. Prefer tuning `AgentWorkspaceRoots`,
`AgentPublishRoots`, `HighRiskFilePathIndicators`, `HighRiskFileExtensions`,
and `SensitiveFileNameIndicators` to match the user's machine. Do not disable
the entire `File` category unless the operator accepts losing those guardrails.

For every tuning change, be able to explain:

- the repeated alert pattern
- why it is expected on this machine
- which config key changed
- what evidence remains visible locally
- what risk the user accepts

Prefer `config\policy-rules.json` for narrow local allow/block tuning when the
operator wants local evidence preserved. Start from
`config\policy-rules.example.json`, keep entries disabled until reviewed, then
run:

```powershell
& "C:\Program Files\Arcane EDR\bin\ArcaneEDR.exe" --policy-preview --last 24h
```

When a proposed rule needs review before matching telemetry exists, preview a
sample rule or redacted sample alert JSON:

```powershell
& "C:\Program Files\Arcane EDR\bin\ArcaneEDR.exe" --policy-preview --sample-rule NET-BEACON-TIMING-LOW-RISK --sample-process codex.exe --sample-score 55
& "C:\Program Files\Arcane EDR\bin\ArcaneEDR.exe" --policy-preview --sample-rule NET-EGRESS-PORT-MISUSE --sample-process ssh.exe --sample-ip 192.168.1.50 --sample-port 22 --sample-user operator
& "C:\Program Files\Arcane EDR\bin\ArcaneEDR.exe" --policy-preview --sample-alert .\sample-alert.json
```

Sample preview options can express process, parent process, user, destination
domain, IP, port, path, signer, hash, and command text. Use them to test the
exact match fields in a proposed policy entry before enabling it.

Use `suppress_external` to stop repeated external notifications while retaining
local alert logs, incident grouping, daily report context, and support-bundle
summaries. Use `DisabledRuleIds` or `DisabledRuleCategories` only when the
operator accepts that matching evidence will disappear before local logging.

Do not edit source code for a local false positive. If the rule itself appears
wrong in a general product sense, explain the evidence and ask whether the user
wants product-development help.

## Actionability And Report Language

Arcane reports should help the operator answer one question quickly: "Is this
machine likely compromised, or does this need review?" Tune language and
notification behavior so the product is neither scary by default nor timid when
evidence is strong.

Use a confidence ladder when interpreting alerts, daily reports, or AI
analysis:

- Confirmed or highly likely compromise: use direct language only when there is
  strong corroboration, such as known malicious indicators, blocked hashes,
  unauthorized persistence plus suspicious execution, suspicious remote access
  plus privilege/persistence changes, or clear egress/C2 behavior tied to an
  unexpected process.
- Needs review: use this for high-signal but incomplete evidence, especially
  when source-event details, process lineage, destination identity, or operator
  context is missing.
- Watch or baseline: use this for repeated lower-confidence signals, expected
  agent/backend activity, maintenance windows, standalone special-privilege
  events, ambiguous session broker events, and volume-only patterns.
- Expected local context: use this only when recent operator action, local
  config, signer/path/process identity, and repeated baseline evidence make the
  benign explanation durable.

Avoid scary language unless the evidence earns it. Prefer phrases such as:

- "No confirmed compromise from available evidence."
- "Needs review because the evidence is high-signal but incomplete."
- "Worth watching during baseline tuning."
- "Expected if this matches the operator's recent activity."
- "Escalate if this was not initiated by the operator."

Also avoid under-reporting. If a signal is potentially dangerous but
incomplete, name both sides: what is concerning, what context could make it
benign, and what evidence would change the assessment. Do not dismiss a pattern
solely because it involves a known agent process, a trusted path, or high alert
volume.

For daily reports:

- Put the high-level determination near the top.
- Keep the high-level determination, compromise assessment, recommended next
  step, and critical callouts deterministic from local telemetry. AI output
  belongs in a clearly labeled secondary review section.
- Keep critical callouts concise, but include process/source context when
  available.
- Treat volume as context, not proof.
- Explicitly mention false-positive factors such as baseline learning,
  maintenance context, agent context, telemetry gaps, and stale investigation
  activity.
- Make the recommended next step concrete and bounded, for example review a
  process lineage, confirm an RDP session, inspect a persistence item, or tune a
  local allowlist.

For local tuning decisions:

- Reduce external alerting only after a repeated benign pattern is understood.
- Keep local evidence logged even when emails are dampened.
- Prefer narrow config keys over broad category suppression.
- Revisit a tuning decision when new evidence appears over the next few days.
- Document whether the change is host-specific local context or a general
  product improvement candidate.
- Check `PersistEventLogWatermarks` and `EventLogWatermarkFile` before treating
  repeated post-restart PowerShell, Windows, or Sysmon alerts as new activity.
  Restart replay should be fixed at the watermark/state layer; real new records
  still need normal review.

Examples of local evidence that may inform config or docs, not source-level
hard-coding:

- Hyper-V host-to-guest login can appear as Windows logon type `10` with source
  `0.0.0.0`; treat this as ambiguous local/session-broker context unless other
  remote-access evidence is present.
- Expected agent backend traffic can resemble low-jitter HTTPS beaconing.
- Windows `4672` special-privilege events are common around services, desktop
  sessions, and admin activity, and become meaningful mostly when paired with
  other suspicious context.
- `AUTH-REMOTE-SPECIAL-PRIVILEGES` is more meaningful than a standalone
  `AUTH-SPECIAL-PRIVILEGES` because it correlates privilege assignment with
  recent remote logon activity for the same account.

## AI Analysis

AI compact analysis is a secondary triage signal, not final authority.

- Payloads should remain compact, bounded, and redacted.
- Use `--preview-ai-payload` to see what would be sent without making an API
  call.
- Use `--test-ai-analysis` only when the operator wants a fresh API call.
- If an AI provider marks a sample alertable, inspect whether the aggregate window
  includes stale or already-explained alerts.
- Normal alert email behavior depends on configured score thresholds.

## Privacy And Secrets

- Never commit live config files, secrets, API keys, recipient addresses, raw
  private logs, or machine-specific credentials.
- Keep machine-specific values in ignored local config files:
  - `config\ArcaneEDR.config`
  - `config\Deployment.config`
- Prefer redacted summaries when discussing logs.
- Be careful with command lines, script blocks, user names, paths, IPs, URLs,
  and email addresses in public artifacts.

## Validation Checklist

Before presenting local setup as complete:

```powershell
.\scripts\build.cmd
.\bin\ArcaneEDR.exe --validate-config
```

For live deployment checks, when explicitly requested:

```powershell
.\scripts\run-admin-task.cmd PublishRestart
.\scripts\run-admin-task.cmd ValidateAdmin
sc.exe query ArcaneEDR
& "C:\Program Files\Arcane EDR\bin\ArcaneEDR.exe" --alert-volume --last 10m
```

When working in Git:

- Check `git status --short` before editing.
- Do not commit ignored local config, secrets, logs, or machine-specific data.
- Do not revert user changes unless explicitly asked.
- Do not create commits or pushes unless the operator asks.

## Response Safety

Arcane may include response features, but active response is high risk.

- Do not kill processes, add firewall blocks, or remove persistence unless the
  operator explicitly asks.
- Prefer dry-run or manual response paths.
- If containment is requested, explain the target, evidence, expected effect,
  and rollback path before acting.

## Communication Style

Be clear about uncertainty. Use plain language:

- "This is expected given the operator action."
- "This is worth watching, not confirmed compromise."
- "This is concerning only if you did not initiate that session."
- "This should be tuned as local context, not hard-coded into the product."

The operator owns the workstation. Your role is to make the evidence easier to
understand and the changes safer to make.
