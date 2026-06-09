# Arcane EDR Roadmap

This roadmap describes the work needed to move Arcane EDR from beta to a stable
`v1.0.0` release. The current project is useful and operational, but `1.0.0`
should mean the install flow, upgrade path, alert volume, privacy model, and
response behavior are predictable.

The north star is specific: Arcane should make unattended agent workstations as
safe as practical while still allowing bleeding-edge local work. It should
provide useful host-level detection, alerting, privacy controls, and constrained
admin workflows without requiring a paid enterprise EDR, SIEM, MDM, or SOC
deployment.

## Release Targets

- `v0.1.x-preview`: functional preview, GitHub-safe config templates, service
  install, logging, Brevo alerting, Sysmon ingestion, AI compact analysis,
  baseline learning, and daily summaries.
- `v0.2.0`: install, upgrade, validation, and packaging hardening.
- `v0.3.0`: detection quality, false-positive reduction, and per-rule tuning.
- `v0.4.0`: modular notification and reporting framework.
- `v0.5.0`: investigation MVP, rule explanations, safe simulations, and
  user-friendly granular detection policy.
- `v0.6.0`: agentic workstation guardrails MVP and active-response dry-run.
- `v0.7.0`: collector/rule interface cleanup and privacy hardening.
- `v0.8.0`: full feature-complete local product milestone with MSI
  installer/uninstaller, best-in-class Windows GUI for configuring and
  maintaining the service, and a locked service/GUI alignment strategy.
- `v1.0.0`: documented stable release with tested install, upgrade, alerting,
  privacy, recovery behavior, and a clear mission as an agent-workstation safety
  layer.

## Milestone Execution Policy

Work should finish the active milestone before moving to the next milestone
whenever that is practical. A later milestone may be touched early only when it
unblocks the active milestone, prevents avoidable rework, fixes an urgent
operational issue, or is a very small adjacent change with low risk.

Because the project is still pre-`v1.0.0`, prefer active refactoring toward
unified product surfaces over preserving backwards-compatibility hacks. Do not
add compatibility shims unless the operator explicitly asks for one; removed
surfaces should fail validation loudly instead of being quietly honored. Avoid
partial implementations that look supported but only work through aliases or
proxy behavior; a feature should be called supported when config, validation,
runtime behavior, logging, reports, and docs all share the same model.

Starting with the `v0.8.0` track, Arcane should be developed as a coupled
service plus Windows GUI product. New service capabilities should have matching
GUI configuration/maintenance surfaces, validation, documentation, and installer
coverage unless the operator explicitly scopes them out. The GUI should stay in
lockstep with the service feature set instead of becoming a stale wrapper around
older config.

Current active milestone: `v0.8.0` planning. `v0.7.0` is released and deployed
locally.

Recently completed `v0.7.0` gate:

- Shared rule taxonomy now centralizes rule categories, lifecycle IDs,
  response follow-up IDs, direct notification-path rules, and common
  prefix/category decisions.
- Remote endpoint enrichment adds DNS-derived names plus bounded optional rDNS
  and RDAP owner/ASN/country context without blocking the poll indefinitely.
- Ordered remote endpoint policy is the single remote allow, trust, block, and
  critical review surface. Removed split remote-list keys now fail validation
  loudly instead of being honored through compatibility shims.
- Default policy elevates RDAP country missing and non-US country context to
  critical review while preserving operator-controlled local tuning.
- Remote endpoint policy validation catches unsupported actions, invalid CIDRs,
  malformed ports, invalid regex entries, unknown fields, and missing reasons.
- `0.7.0` versioning, local release ZIP, checksum, package contents, bundled
  example-config validation, GitHub release, and local deployment are complete.

## Milestone Status

This section is the high-level completion tracker. Detailed work remains in the
phase sections below.

| Milestone | Status | Completion | Notes |
| --- | --- | --- | --- |
| `v0.1.x-preview` | Done | Complete | Functional preview: service, local logging, Brevo alerting, Sysmon ingestion, AI compact analysis, baseline learning, and daily summaries. |
| `v0.2.0-beta` | Done | Complete | Tagged beta with install, upgrade, validation, package-release script, config preservation, and scheduled-task admin bridge. |
| `v0.3.0` | Done | Complete | Detection-quality work is released as `v0.3.0`; further empirical tuning feeds later milestones. |
| `v0.4.0` | Done | Complete | Modular alert sinks are released for Brevo, SMTP, webhook, generic HTTP/API, Windows Event Log, and local JSONL. Daily report preview, local archive, selectable sections, row limits, independent report destinations, canonical destination names, and concurrent AI provider fan-out are released in `v0.4.0`. |
| `v0.5.0` | Done | Complete | Released investigation MVP: `why` explanations, incident grouping, timeline command, support bundle, simulations and demo path, rule-family docs, poll-stage fail-isolation, and structured local detection-policy preview/tuning. |
| `v0.6.0` | Done | Complete | Released guardrails and response-safety milestone: Agent Profile labeling, file-write guardrails, compact activity ledger, alert-only admin/secret/supply-chain guardrails, response dry-run ledger, active-response policy gates, rollback helpers, follow-up detections, maintenance session markers, `0.6.0` versioning, package ZIP, checksum, GitHub release, and local deployment are complete. |
| `v0.7.0` | Done | Complete | Released collector/rule cleanup and privacy-hardening milestone: shared rule taxonomy cleanup, remote endpoint enrichment, ordered remote endpoint policy, default critical country review for RDAP country missing or non-US, no-shim validation for removed remote-list config keys, policy regex/port validation, `0.7.0` versioning, package ZIP, checksum, GitHub release, and local deployment are complete. |
| `v0.8.0` | Planned | Not started | Full feature-complete local product milestone: MSI installer/uninstaller, best-in-class Windows GUI application for configuration and service maintenance, and permanent service/GUI feature-set alignment. |
| `v1.0.0` | Not ready | Planned | Requires completed docs, tuned alert volume, tested install/upgrade/release flow, dry-run/manual response safety, and stable privacy/operations posture. |

Current milestone focus: prepare the `v0.8.0` GUI and MSI track using
`docs\v0.8-gui-and-msi-research.md` as the planning baseline. Do not start live
installer/GUI deployment work without explicit operator scope.

## `v0.8.0` Feature Complete Installer And GUI

`v0.8.0` is the full feature-complete local product milestone. It should move
Arcane from a powerful service-plus-config repo into a best-in-class Windows
application that an operator can install, understand, configure, validate,
maintain, and uninstall without hand-editing files for normal workflows.

Required for `v0.8.0`:

- Use `docs\v0.8-gui-and-msi-research.md` as the planning baseline for GUI
  framework choice, UX standards, installer behavior, service/GUI alignment,
  and validation gates.
- MSI installer and uninstaller with clean install, upgrade, repair, uninstall,
  and rollback behavior.
- A full Windows GUI application for service configuration, health, validation,
  policy editing, alert/report review, support bundle generation, maintenance
  windows, and safe response rollback workflows.
- GUI and service feature sets must stay coupled going forward. New service
  features should ship with matching GUI controls, validation, help text,
  docs, and installer/update considerations unless explicitly scoped out.
- GUI changes should use the same canonical config, policy, validation, and
  status model as the service. No duplicate hidden config model, no stale UI
  settings, and no compatibility shims unless explicitly requested.
- Operator safety remains central: `AlertOnly` stays default, active-response
  controls remain explicit, rollback paths are visible, and risky actions are
  understandable before execution.
- Release packaging should make the MSI, service binary, GUI binary, examples,
  docs, checksums, and version metadata coherent as one product.

Exit criteria:

- A fresh Windows install can be completed from the MSI and validated from the
  GUI without manual file edits.
- The GUI can configure every supported service feature intended for normal
  operator use in that release.
- The GUI can show service state, validation results, recent alerts, report
  status, policy file state, and response rollback state.
- MSI uninstall removes installed binaries/tasks/service entries cleanly while
  preserving or explicitly offering to remove local evidence/config according
  to documented operator choice.
- `--validate-config`, GUI validation, docs, and installer behavior agree on the
  same supported feature set.

## `v1.0.0` Scope Boundary

`v1.0.0` should be a stable local safety layer, not an enterprise EDR clone.
Features should make unattended agent workstations safer while preserving a
small install footprint and predictable behavior.

Required for `v1.0.0`:

- Reliable install, upgrade, uninstall, validation, and release packaging.
- Documented source-vs-live deployment policy: normal source changes are not
  redeployed, and live deployment happens only for tagged releases or explicit
  operator requests.
- Complete documentation for install, configuration, operations, privacy,
  alerting, upgrades, troubleshooting, and release verification.
- Stable service recovery, startup notifications, daily summaries, and log
  retention behavior.
- Manageable alert volume after baseline tuning.
- Modular alert sinks with Brevo, SMTP, webhook, and generic HTTP/API support.
- Optional compact AI analysis with documented redaction and hard payload caps.
- Explainable alerts, safe simulation scripts, and a local support bundle.
- Local-only incident grouping and timeline commands for recent related alerts.
- Agent-aware detection and labeling for known unattended agent processes.
- Dry-run or manual-only active response. Automatic containment remains off by
  default.

Deferred beyond `v1.0.0`:

- Fleet console, cloud management, and central policy.
- Human MDR workflows, case management, and analyst handoff.
- Full identity/SaaS monitoring.
- Deep AI governance, prompt inspection, memory inspection, or tool-permission
  policy engines.
- Automated broad containment without a rollback ledger and strong safeguards.
- Deep reputation feeds, ransomware canary management, and deception features.

## Phase 1: Stabilize The Current Beta

- Run with `BaselineLearningMode=true` for at least 24 hours, preferably 48-72
  hours on noisy workstations.
- Review alert volume by rule, process, and severity.
- Tune known local noise from development tools, browsers, update agents, and
  expected Windows services.
- Keep `ResponseMode=AlertOnly` during baseline collection.
- Confirm service health remains stable.

Exit criteria:

- `PollFailures=0` during normal operation.
- `ExternalSendFailures=0` after alert configuration is complete.
- No recurring high or critical false positives.
- Daily summary arrives at the configured local time.
- AI compact analysis does not alert on ordinary baseline noise.

## Phase 2: Install And Upgrade Hardening

- Test a fresh clone on a clean Windows VM.
- Test install, stop, start, uninstall, reinstall, and upgrade.
- Verify publish preserves existing machine-specific configs:
  - `config\ArcaneEDR.config`
  - `config\Deployment.config`
- Add a version command, for example `ArcaneEDR.exe --version`. Completed in
  `0.2.0-beta`.
- Add a release packaging script that emits a clean ZIP from tracked files and
  build output.
- Ensure scripts fail loudly on build or deployment errors.

Progress:

- Added central `VersionInfo` and `ArcaneEDR.exe --version`.
- Added `scripts\package-release.ps1` and `scripts\package-release.cmd`.
- Release packaging emits `artifacts\ArcaneEDR-<version>.zip` plus a SHA256
  checksum file.
- The package includes example configs only; live local configs, runtime logs,
  and Sysmon binaries stay out of the ZIP.
- Added constrained scheduled-task admin workflow for approved elevated
  operations without running the Codex desktop app as Administrator:
  `PublishRestart`, `InstallService`, `UninstallService`, `InstallSysmon`, and
  `ValidateAdmin`.
- Locked the scheduled-task elevation model as the preferred admin workflow in
  `docs\elevation-strategy.md`.
- Confirmed the bridge with `ValidateAdmin`: elevated validation can read
  protected event logs, write to `C:\Security`, and returns `LastTaskResult: 0`.

Exit criteria:

- A user can go from fresh clone to running service using only the README.
- Normal `publish.cmd` never wipes live machine config.
- Ordinary source and documentation changes can be built and validated without
  touching the live service.
- Service recovery restarts the service after a forced crash.
- Release artifacts are reproducible enough to checksum.

## Phase 3: Detection Quality

- Add per-rule enable/disable and per-rule minimum email score.
- Add rule categories such as `Network`, `PowerShell`, `Persistence`, `Auth`,
  `Sysmon`, `AI`, and `Health`.
- Improve Microsoft-signed scheduled-task and service trust handling.
- Add maintenance-context labeling for expected build, publish, install, and
  validation commands without hiding local evidence.
- Reduce repeated low-value alerts from the same stable process and behavior.
- Improve localhost-only listener classification.
- Make weak standalone signals correlation-first: timing-only beaconing,
  direct-IP HTTPS, and special-privilege auth events should generally stay
  local/low unless paired with suspicious process lineage, unsigned or
  user-writable binaries, persistence, PowerShell staging, risky ports, blocked
  intelligence, failed-logon bursts, or unknown remote access.
- Add explicit LAN ingress/egress classification for high-signal lateral
  movement awareness:
  - distinguish private-network outbound sessions from internet egress
  - classify private-network inbound sessions to local listeners where direction
    can be inferred
  - keep normal LAN chatter low/no alert, but escalate untrusted access to
    admin, file-sharing, remote-management, or lateral-movement ports
  - include process, parent, signer, local/remote endpoint, and listener context
    in alert entities
- Keep high and critical alerts rare and actionable.

Progress:

- Added central rule categories derived from rule IDs and included category in
  alert JSON, email/plain-text formatting, Windows Event Log alerts, local
  logs, retry queue state, incident records, and support-bundle summaries.
- Added machine-local system time, Windows time-zone ID, and UTC offset to alert
  JSON, email/plain-text formatting, Windows Event Log alerts, local logs,
  retry queue state, compact AI alert context, agent activity summaries, and
  support-bundle summaries.
- Added config-driven rule policy:
  - `DisabledRuleIds`
  - `DisabledRuleCategories`
  - `RuleMinimumEmailScores`
  - `CategoryMinimumEmailScores`
- Added maintenance-context tuning:
  - `EnableMaintenanceContext`
  - `MaintenanceContextTermGroups`
  - `MaintenanceContextExternalAlertMinimumScore`
- Maintenance-context matches are labeled in alerts, logs, incidents, support
  bundles, and compact AI metadata, while external delivery is dampened only
  below the configured maintenance threshold.
- Split unexpected listener alerts into lower-severity localhost-only listener
  rules and higher-severity reachable listener rules, and limited inbound
  listener correlation to non-loopback TCP listeners.
- Added external-only low-value repeat dampening so stable low-score behavior
  can stop repeating notifications while remaining visible in local logs and
  incidents.
- Added conservative trusted-location variants for service installs and
  scheduled-task changes when trusted name/path indicators match and suspicious
  impersonation traits are absent.
- Extended persistence trust handling to inspect scheduled-task action XML,
  resolve local service/task executable signer subjects, and use configured
  trusted signer fragments such as Microsoft signer subjects. Trusted variants
  still require a trusted name plus trusted path or signer evidence, and broad
  user-writable indicators are overridden only when trusted name, path, and
  signer evidence all match.
- Added `ArcaneEDR.exe --alert-volume --last <duration>` to summarize recent
  local alert volume by severity, category, rule, and process, including an
  external-delivery qualification estimate before provider, rate-limit, retry,
  or repeat-dampening behavior. It now also prints a baseline-off external
  delivery projection so operators can check whether disabling baseline
  learning would flood notifications before changing live config.
- Added baseline-off projection driver summaries by rule and process, plus a
  starter `RuleMinimumEmailScores` profile in the example config for weak
  standalone discovery signals that should remain local-first by default.
  `--alert-volume` now also prints compact current/baseline-off external
  candidate examples with time, score, rule, process, maintenance context, and
  title so operators can inspect likely notification drivers without exposing
  raw alert entities or command lines.
- Added `ArcaneEDR.exe --poll-once` to collect one monitor poll and exit
  without starting the service or writing service lifecycle health state, making
  short local alert-volume samples easier to collect.
- Used one-shot samples to tune clear local noise: the example sandbox profile
  now treats the Codex app itself as trusted for routine outbound app traffic,
  and the persistence inventory skips Startup-folder `desktop.ini` metadata.
  In the local sample this reduced a one-poll alert burst from 22 alerts to one
  local-only Codex unusual-port notice.
- Live local publish/restart validation succeeded via the constrained admin
  bridge. Elevated validation from the published app passed with event-log
  access, and a post-fix live alert-volume check showed zero external-qualified
  alerts in the tight validation window.
- Suppressed built-in PowerShell ScheduledTasks cmdletization scaffolding so
  generated module script blocks do not alert as persistence commands while
  actual service, scheduled-task, Run-key, and startup persistence commands
  remain alertable.
- Added parent/source process enrichment for PowerShell Operational events when
  the associated process is still observable at collection time.
- Added `PS-ENCODED-APP-INVENTORY` so encoded Start-app/process/UserAssist
  inventory is recorded as medium-severity context instead of being treated as a
  generic critical encoded-command alert.
- Tightened encoded-command switch matching so ordinary `-Encoding` parameters
  and `System.Text.Encoding` references do not trigger encoded-command alerts.
- Empirical tuning observations from local baseline:
  - Hyper-V host-to-guest login can produce expected Windows logon type 10 /
    RDP-style alerts with source IP `0.0.0.0`.
  - OpenAI-signed Codex app-server traffic to Cloudflare-backed HTTPS endpoints
    can resemble low-jitter beaconing even when it is expected agent backend
    traffic.
  - Repeated Windows `4672` special-privileges events around expected service,
    desktop, and Hyper-V session activity are low-value unless paired with
    unexplained remote logon, process staging, or persistence changes.
- Product-level tuning candidates from local baseline:
  - Beacon rules should not treat timing regularity alone as critical when the
    process is signed, expected, using normal HTTPS, and lacks paired risk.
  - Agent-context should support external-alert dampening for known signed agent
    traffic while preserving local evidence.
  - Direct-IP HTTPS should use signer, path, parent, and repetition context so
    trusted updaters and OS task hosts do not repeatedly look like compromise.
  - `4672` special-privilege auth events should remain correlation-first rather
    than becoming noisy standalone escalations.
- Implemented correlation-first network tuning for weak standalone signals:
  low-risk signed direct-IP web egress is recorded as
  `NET-DIRECT-IP-WEB-EGRESS-SIGNED`, and timing-only beacon-like behavior from
  expected signed normal-web processes is recorded as
  `NET-BEACON-TIMING-LOW-RISK` unless paired high-risk context is present.
  Trusted signed processes using common alternate web/proxy ports such as
  `8080` or `8443` are recorded as `NET-EGRESS-TRUSTED-ALT-WEB-PORT` instead
  of high-priority port alerts.
- Reduced duplicate network context by suppressing the generic
  `NET-EGRESS-NEW-UNTRUSTED` alert when a more specific endpoint finding has
  already explained the same connection.
- Added process-specific outbound port tuning via `ProcessAllowedOutboundPorts`
  so nonstandard ports can be treated as normal for a named process without
  globally allowlisting the port for every process.
- Added explicit high-signal LAN lateral movement classification:
  `NET-LAN-INBOUND-LATERAL-PORT` for inferred private-network inbound sessions
  to local lateral/admin listeners, and `NET-LAN-EGRESS-LATERAL-PORT` for
  untrusted outbound connections to lateral/admin ports on private-network
  hosts.
- Tuned authentication noise around Windows special-privilege events:
  standalone `4672` events are lower-severity local context and repeat-dampened
  per principal, while `AUTH-REMOTE-SPECIAL-PRIVILEGES` preserves stronger
  context when special privileges occur near recent remote logon activity.
  Remote-style logons with unspecified sources such as `0.0.0.0` are classified
  as low-risk session context instead of ordinary remote source evidence.
- Reworked the daily summary into a customer-facing daily report that supports
  the v0.3 tuning loop: quick compromise assessment, report verdict,
  confidence, recommended next step, compact tables for critical callouts,
  health, signal summary, false-positive context, high-signal review,
  automation activity, tuning notes, and optional AI daily analysis using a
  false-positive-aware report prompt instead of the hourly alertability prompt
  or generic alert email template. The top-level report determination and
  critical callouts now remain deterministic local-telemetry sections, with
  AI output confined to a labeled secondary review section.
- Added persisted event-log watermarks for Windows, PowerShell, and Sysmon
  ingestion so service restarts and publish/restart cycles do not recycle the
  same recent event records into fresh alerts or daily-report counts. Watermark
  handling keeps a reset/cleared-log escape path when newer events arrive with
  lower record IDs.

Exit criteria:

- Normal workstation activity produces manageable log volume.
- Email and external alerts are actionable.
- Baseline learning can be disabled without causing a flood.
- High-confidence detections remain visible after local tuning.

## Phase 3.25: Investigation MVP

`v1.0.0` should make alerts easier to trust, reproduce, and investigate without
building a case-management system.

Required for `v1.0.0`:

- Add structured alert reason blocks, for example `why`, that explain the
  conditions that caused an alert.
- Add lightweight local incident grouping by host, user, root process or
  process family, and a short time window such as 30 minutes.
- Store incident state locally in a file-backed format such as JSONL.
- Add commands for local investigation:
  - `ArcaneEDR.exe --incidents --last 24h`
  - `ArcaneEDR.exe --timeline <incident-id>`
- Include first seen, last seen, related alerts, compact timeline, and
  recommended manual actions for each incident.
- Add a support bundle command:
  - `ArcaneEDR.exe --support-bundle`
- Support bundle output should include version, redacted config, service health,
  recent alerts, recent errors, enabled collectors, enabled alert sinks, Sysmon
  availability, and event-log access checks.
- Keep support bundles privacy-first: no secrets, no raw prompt contents, no
  raw command output dumps, and bounded log volume.
- Add safe simulation scripts for representative detections:
  - encoded PowerShell or encoded-command telemetry
  - unexpected local listener
  - scheduled task or service persistence
  - agent activity outside configured workspace
  - response dry-run
- Add one simple benign/suspicious/cleanup demo path that proves the detection
  loop end to end.
- Add lightweight rule documentation for v1 rules or rule families with:
  - rule ID
  - what it detects
  - required telemetry
  - why it matters
  - common false positives
  - tuning knobs
  - safe test command
  - expected alert shape

Deferred beyond `v1.0.0`:

- Analyst comments.
- Case ownership and workflow status.
- Multi-host correlation.
- Central dashboard.
- Long-term searchable database.
- Complex query language.

Progress:

- Added structured `why` alert metadata at dispatch time. The explanation is
  included in local JSONL, local text logs, email/SMTP formatting, Windows Event
  Log alerts, webhook/generic HTTP JSON payloads, and queued retry delivery.
- Added a local incident grouping MVP backed by `ArcaneIncidents.jsonl`, plus
  `--incidents --last <duration>` and `--timeline <incident-id>` commands for
  recent summary and timeline review.
- Added `--support-bundle` to generate a bounded local folder with version,
  redacted config, health state, collector/sink/runtime checks, summarized
  alerts, recent warning/error lines, and incident summaries.
- Added `scripts\simulate-detection.cmd` / `.ps1` for safe representative
  simulations covering encoded PowerShell, unexpected localhost listener, and
  scheduled-task persistence telemetry.
- Added `scripts\simulate-detection.cmd -Scenario Demo` as a compact
  benign/suspicious/cleanup demo path for first-run validation.
- Added `docs\rule-family-reference.md` covering current rule families,
  required telemetry, value, false positives, tuning knobs, safe tests, and
  expected alert shape.

Exit criteria:

- A new user can run a safe simulation and see the expected local alert.
- A real alert explains why it fired without requiring source-code inspection.
- Related recent alerts can be viewed as a compact local timeline.
- A support bundle can be generated and reviewed without leaking configured
  secrets or private raw payloads.

## Phase 3.5: Agentic AI Workstation Guardrails MVP

Keep this phase narrow for `v1.0.0`. Arcane should harden unattended agent
workstations without trying to become a full enterprise AI governance platform.

Required for `v1.0.0`:

- Add an `AgentProfile` config section for expected agent executables,
  workspace roots, package-manager tools, browser tools, and approved admin
  bridge tasks.
- Label and correlate alerts that involve known agent processes, their child
  shells, and approved workspaces.
- Alert when known agent processes write outside approved workspace or publish
  roots.
- Add high-confidence malicious file-behavior indicators without broad
  file-auditing:
  - executable or script drops into Startup, Run-key target paths, scheduled-task
    action paths, service binary paths, browser extension locations, or other
    persistence-adjacent locations
  - user-writable executable/script drops followed by execution, network egress,
    PowerShell staging, or persistence within a short window
  - archive/download/extract/run chains launched by agent child shells or
    package-manager tooling outside approved workspace roots
  - credential, token, SSH-key, certificate, or `.env` material created or
    touched by unexpected processes outside approved project roots
- Alert when known agent processes invoke unexpected elevation paths, service
  creation, scheduled tasks, firewall changes, registry persistence, or ACL
  changes outside approved maintenance scripts.
- Add a compact agent activity ledger that records high-risk process trees,
  parent process, command category, touched paths, remote endpoint category, and
  rule hits without storing raw sensitive payloads by default.
- Add simple secret-exposure indicators for commands or script blocks that
  reference high-risk token names, credential files, cloud keys, SSH material,
  or browser credential stores.
- Add package-install and supply-chain indicators for `npm`, `pip`, `curl`,
  `Invoke-WebRequest`, `git clone`, unsigned downloads, and install scripts run
  by agent-launched shells.
- Add a maintenance/session marker so expected publish, package, install, and
  validation work can be labeled without globally suppressing detections.

Deferred beyond `v1.0.0`:

- Deep secret scanning of file contents, prompts, transcripts, browser data, or
  model memory.
- Whole-disk file auditing, generic document-change monitoring, or DLP-style
  content inspection.
- Egress drift intelligence by ASN, dynamic DNS, paste sites, file-sharing
  services, and destination reputation.
- Automatic agent kill-switch behavior. A manual or dry-run containment command
  can exist in `v1.0.0`, but broad automated blocking should wait.
- Fine-grained tool permission policy, prompt firewalling, or AI governance
  workflows.

Exit criteria:

- Agent-specific guardrails improve signal without requiring enterprise
  identity, SIEM, or MDM integration.
- Raw prompts, secrets, command output, and private file contents are not stored
  or sent externally by default.
- Expected agent development work can be labeled and reviewed without hiding
  genuinely unusual behavior.
- Response remains `AlertOnly` by default.

Progress:

- Added `AgentProfile` config fields for known agent processes, child shells,
  workspace roots, publish roots, package-manager tools, approved admin tasks,
  and secret-indicator terms.
- Added dispatch-time alert annotation with `AgentContext` details and
  `agent_context=` entity metadata. This labels existing alerts without
  changing score, cooldown, delivery thresholds, or response behavior.
- Added narrow Sysmon-backed high-signal file-create guardrails:
  `FILE-HIGH-RISK-EXECUTABLE-DROP`,
  `FILE-HIGH-RISK-DROP-SUSPICIOUS-WRITER`,
  `FILE-AGENT-EXECUTABLE-DROP-OUTSIDE-ROOT`,
  `FILE-SENSITIVE-MATERIAL-TOUCHED`, and `FILE-DROP-THEN-EXECUTION`. The
  bundled Sysmon policy emits only selected FileCreate targets such as Startup
  folders, scheduled-task storage, browser extension paths, and
  sensitive-looking filenames; Arcane then requires executable/script,
  suspicious-writer, agent-root, sensitive-name, or execution correlation.
- Added a compact agent activity ledger for agent-involved alerts above a
  configured score. It writes sanitized JSONL records with rule, score, process
  family, agent reason labels, command category, endpoint category, and file
  category, plus `ArcaneEDR.exe --agent-activity --last <duration>` for local
  review. Raw command lines, file paths, users, IPs, URLs, and alert bodies are
  not stored in the ledger.
- Added the first alert-only agent admin-command guardrail:
  `AGENT-ADMIN-COMMAND` detects agent-initiated elevation, scheduled-task,
  service, firewall, ACL, registry persistence, and security-control command
  terms outside configured `AgentApprovedAdminTaskNames`. This records local
  evidence and compact ledger context without changing `ResponseMode`.
- Added alert-only agent secret-reference and supply-chain guardrails:
  `AGENT-SECRET-REFERENCE` detects configured token, key, credential, SSH,
  certificate, cloud-secret, and browser credential-store indicators in
  agent-adjacent telemetry, while `AGENT-SUPPLY-CHAIN-COMMAND` detects
  package installs, source clones, downloads, install scripts, and
  expression-execution indicators from agent-launched contexts.
- Added dry-run response modes and a compact local response ledger so operators
  can see proposed firewall-block and process-termination actions before
  enabling active response.
- Added explicit active-response safety gates so firewall blocks and process
  termination require separate opt-in config, and active response requires the
  local response ledger.
- Added a response policy layer so active response requires explicit
  `ResponseAllowedRuleIds` or `ResponseAllowedCategories` entries, while
  blocked rule/category lists and protected process names keep agent, test,
  health, AI, baseline, response-follow-up, browser, Git, development, and core
  Windows processes out of automatic containment by default.
- Added `ArcaneEDR_BLOCK_<response-id>` firewall rule naming, response-ledger
  mapping back to the trigger alert, and `ArcaneEDR.exe --response-firewall` for
  listing or removing Arcane-owned firewall block rules.
- Added response follow-up detection for process respawn after Arcane
  termination, with separate external-notification thresholding to avoid email
  or webhook floods.
- Added bounded maintenance session markers via `ArcaneEDR.exe --maintenance`
  so expected publish, package, install, and validation windows can be labeled
  without suppressing local evidence.
- Bumped `VersionInfo` to `0.6.0` and generated a local release package plus
  SHA256 checksum under `artifacts\ArcaneEDR-0.6.0*`. The staged package binary
  reports `Arcane EDR 0.6.0` and validates its bundled example config.
- Tagged and pushed `v0.6.0`, published the GitHub release with ZIP and checksum
  assets, and deployed locally via `PublishRestart`. Admin validation passed
  after deployment with 0 errors and 0 warnings.

## Phase 4: Modular Notification And Reporting

Brevo should be one notification sink, not the notification architecture.

- Add `CompositeAlertSink` to fan out to multiple alert sinks.
- Add per-sink enablement, minimum score, rate limiting, and failure isolation.
- Keep sink failures from blocking the core monitor loop or other sinks.
- Share alert formatting across sinks.
- Keep secrets in environment variables, Windows Credential Manager, or another
  secret provider, not in tracked config.

Required `v1.0.0` alert sinks:

- `BrevoEmailAlertSink`
- `SmtpEmailAlertSink`
- `WebhookAlertSink`
- `GenericHttpApiAlertSink`
- `WindowsEventLogAlertSink`
- `LocalJsonlAlertSink`

Candidate post-`v1.0.0` alert sinks:

- `SlackAlertSink`
- `TeamsAlertSink`
- `DiscordAlertSink`
- `SyslogAlertSink`
- `NtfyAlertSink`
- `PushoverAlertSink`

Progress:

- Added `CompositeAlertSink` fan-out with per-sink failure isolation.
- Added required `v1.0.0` sink implementations for Brevo, SMTP, webhook,
  generic HTTP/API JSON POST, Windows Event Log, and local JSONL.
- Added config loading and validation for supported sink providers and
  provider-specific secrets.
- Added `ExternalAlertProviderMinimumScores` so each configured sink can have
  its own score floor after global, rule, and category external thresholds.
- Added `ExternalAlertProviderMaxPerHour` so each configured sink can have an
  optional hourly delivery cap in addition to the global alert rate limits.
- Added a daily report archive path with configurable Markdown/JSON output,
  selectable report sections, and row limits for critical callouts,
  high-signal details, bucket summaries, and automation summaries. The JSON
  archive stores redacted aggregate report metadata rather than raw alert
  bodies or entities.
- Added `ArcaneEDR.exe --preview-daily-report` with Markdown output by default,
  `--json` for redacted archive payload preview, and `--archive` for explicit
  local archive writes without sending external notifications or calling
  the AI provider.
- Added `DailyReportDestinations` so scheduled and test daily reports can be
  routed to `ExternalAlertSinks`, `LocalArchive`, or archive-only reporting
  without changing normal real-time alert sinks.
- Added a report-specific webhook destination that posts the redacted daily
  report JSON payload without reusing normal alert webhook schema.
- Collapsed daily report destination matching to the canonical
  `ExternalAlertSinks`, `LocalArchive`, and `Webhook` names so the public
  reporting surface does not depend on compatibility aliases.
- Added `ArcaneEDR.exe --validate-config <config-path>` so cloned or staged
  deployments can validate a specific machine-tuned config without copying it
  into the runtime config directory first.
- Added an `IAiAnalysisProvider` foundation with concurrent `AIAnalysisProviders`
  fan-out, OpenAI/OpenAI-compatible Responses endpoint support, native
  Anthropic Claude Messages API support, and per-provider config maps for
  models, endpoints, auth headers, API key environment variables, and version
  headers.
- Added active AI provider metadata to support bundles without exposing API
  keys or endpoint URLs.
- Refactored the public AI analysis surface away from OpenAI-specific config,
  report section, alert ID, command, and log naming. The strategy is to keep
  provider-specific names only where they refer to an actual provider adapter.

Reporting should be separate from alerting where useful:

- Daily summary report sink. Initial local archive completed; other report
  destinations remain future work.
- Markdown or JSON report sink. Local archive completed.
- Webhook report sink. Completed.
- Local report archive. Completed.
- Configurable reporting engine with selectable sections, output formats,
  destinations, schedules, and audience-specific tone/detail levels. Initial
  selectable sections, local formats, row limits, and no-send preview command
  completed.

Deferred reporting-engine gaps:

- Additional native report destinations such as Slack, Teams, Discord, syslog,
  ntfy, and Pushover are deferred until the report JSON schema and core sink
  contracts have stayed stable through more local use. Generic webhook already
  covers integration experiments without adding partial native providers.
- Multiple named report profiles, audiences, and tone/detail presets are
  deferred to the user-friendly policy/reporting work because they need a clear
  config model rather than one-off keys.
- Multiple report schedules, recipient groups, and per-destination report
  variants are deferred until the reporting engine has named profiles.
- Custom report templates or a report DSL are deferred because they would be a
  broad configuration surface; current selectable sections and row limits are
  the stable base.
- Report retention, compression, and rotation policy are deferred to later
  operational hardening after archive format usage is better understood.

Exit criteria:

- Multiple sinks can be enabled at once.
- One failed sink does not prevent another sink from receiving an alert.
- Brevo-specific settings are isolated to the Brevo sink.
- Daily reports can be delivered, archived, or previewed independently from
  real-time alert delivery.
- Archived daily reports include a human-readable Markdown report and a
  redacted aggregate JSON payload.

## Phase 5: Modular Collectors, Enrichers, And Rules

Formalize existing separation of concerns so optional features are easy to add
without turning the service into a monolith.

Collector modules:

- `NetstatCollector`
- `SysmonCollector`
- `PowerShellEventCollector`
- `WindowsSecurityCollector`
- `WindowsSystemCollector`
- `PersistenceCollector`
- `DnsCollector`
- Initial collector and poll-stage fail-isolation completed. Netstat, Sysmon,
  individual host telemetry collectors, network analysis, host analysis,
  integrity checks, and per-alert dispatch now continue with remaining work
  after a bounded failure and log a warning/error for review.
  `EnableNetstatCollector` completes the current set of user-facing collector
  toggles.

Enrichment modules:

- `WmiProcessEnricher`
- `AuthenticodeSignerEnricher`
- `HashEnricher`
- `GeoIpEnricher`
- `ReputationEnricher`
- `WhoisAsnEnricher`

Rule modules:

- `INetworkRule`
- `IHostRule`
- `IPersistenceRule`
- `IProcessRule`
- `IDnsRule`
- `IAuthRule`

User-friendly granular detection policy:

- Add a structured policy file, for example `config\policy-rules.json`, for
  machine-specific allow/block tuning without hardcoding local software into
  the product. Initial runtime support completed with an ignored local
  `DetectionPolicyFile`, tracked example template, validation, and recent-alert
  preview command.
- Keep normal cases field-based rather than regex-based. Supported match fields
  should include process name, parent process, signer, path prefix, command
  term group, user/account, rule ID, category, destination domain, IP/CIDR,
  port, and hash.
- Support plain-language actions such as `trusted_context`, `lower_score`,
  `suppress_external`, `raise_score`, `force_alert`, and `tag_only`. Initial
  support completed; `suppress_external` preserves local evidence by default.
- Preserve local logging, incident grouping, and report context by default even
  when a policy suppresses external delivery.
- Require user-friendly metadata on policy entries where practical: `reason`,
  optional `owner`, and optional `expires_utc`.
- Validate policy files with plain-English warnings for unknown fields,
  unsupported actions, invalid CIDRs, expired entries, and risky broad matches.
- Add a preview/test command that explains which policy entries would match a
  sample or recent alert and what action Arcane would take. Initial
  `--policy-preview --last <duration>`, `--sample-rule`, and `--sample-alert`
  support completed, including sample context fields for process, parent, user,
  destination, IP, port, path, signer, hash, and command text.
- Document examples for common tuning tasks so another LLM agent can help a
  user configure Arcane for their own machine without needing to fork or modify
  source code.

Exit criteria:

- Collectors are independently enableable and fail-isolated. Initial support is
  completed for the current collector set, poll analysis stages, and per-alert
  dispatch.
- Rules have IDs, categories, defaults, tests, and per-rule config.
- Optional enrichment can be added without changing detection flow broadly.
- Granular allow/block detection policy is understandable, validated, previewable,
  and preserves local evidence by default.

Progress:

- Started `v0.7.0` rule-interface cleanup with a shared rule taxonomy for rule
  families, categories, lifecycle rule IDs, response follow-up checks, daily
  report classification, alert-volume estimates, incident exclusions, and
  agent activity summaries.
- Added one ordered remote endpoint policy JSON surface for remote allow, trust,
  block, and critical owner/domain/CIDR/country decisions. First enabled match
  wins, default policy elevates RDAP country missing and non-US country to
  critical, and removed split remote-list config keys fail validation.
- Added remote endpoint policy documentation, release/publish packaging for the
  policy example, support-bundle manifest entries, and config-integrity
  monitoring for policy file changes.
- Locked the product strategy that removed surfaces should fail validation
  instead of being carried through compatibility shims unless the operator
  explicitly requests a shim.
- Completed remote endpoint policy validation for invalid regex entries and
  malformed ports, and cleaned the tracked example policy so owner and ASN
  examples do not imply unsupported OR behavior across match fields.
- Bumped `VersionInfo` to `0.7.0`, generated
  `artifacts\ArcaneEDR-0.7.0.zip` plus SHA256 checksum, and validated the staged
  package against its bundled example config with 0 errors. Only expected
  non-admin event-log access warnings remained.
- Tagged and pushed `v0.7.0`, published the GitHub release with ZIP and checksum
  assets, and deployed locally via `PublishRestart`. Admin validation passed
  after deployment.

## Phase 6: Active Response Safety

Active response should stay disabled by default until it is safer and easier to
audit.

- Keep `AlertOnly` as the default response mode.
- Treat dry-run and manual response as the `v1.0.0` target.
- Split response into actions:
  - `FirewallBlockResponse`
  - `TerminateProcessResponse`
  - `DisableScheduledTaskResponse`
  - `StopServiceResponse`
  - `QuarantineFileResponse`
  - `NoopResponse`
- Add dry-run mode for response actions.
- Re-check process identity before killing a PID.
- Add protected process and trusted signer allowlists.
- Build response eligibility from the v0.5 detection policy only after policy
  matches are explainable, validated, and auditable.
- De-duplicate firewall rules.
- Maintain a response ledger for rollback. (Initial ledger exists.)
- Add commands to list and remove Arcane EDR firewall blocks. (Initial
  `--response-firewall` command exists.)
- Restrict active response to high-confidence rules by default:
  - blocked hash
  - blocked domain
  - blocked IP or CIDR
  - known RAT/RMM process
  - encoded PowerShell plus persistence or network correlation

Exit criteria:

- Every dry-run or manual response is logged with rule, target, action, and
  result.
- Firewall blocks can be listed and rolled back.
- Trusted Windows, browser, Git, and development processes cannot be killed by
  broad rules.
- Active response can be tested safely in dry-run mode.
- Fully automatic containment is explicitly out of scope for `v1.0.0`.

## Phase 7: Privacy And Modular AI Analysis

- Keep AI analysis optional and disabled in example config.
- Keep payloads compact, bounded, and redacted.
- Add a command that previews exactly what would be sent.
- Include sanitized aggregate rule, category, score, trend, maintenance-context,
  agent-context, and score-60+ reason buckets so compact analysis has useful
  signal without raw entities.
- Document omitted fields clearly:
  - alert body
  - entity
  - command line
  - script block
  - user
  - path
  - IP
  - URL
  - email
  - secrets
- Consider sending only rule summaries, counters, and score metadata by default.

Modular AI analysis providers:

- Keep `IAiAnalysisProvider` as the analysis architecture so each model vendor
  is one provider, not the product surface.
- Keep direct provider adapters complete enough to validate and document before
  marking them supported.
- Add provider adapters for widely used AI APIs:
  - OpenAI
  - Azure OpenAI
  - Anthropic Claude
  - Google Gemini
  - OpenAI-compatible endpoints
  - Local/self-hosted providers such as Ollama or LM Studio
- Move provider-specific API keys, model names, base URLs, payload limits, and
  timeout settings into config.
- Keep provider secrets in environment variables, Windows Credential Manager,
  or another secret provider rather than tracked config.
- Support disabling AI analysis entirely.
- Support local-only AI analysis for users who do not want security telemetry
  sent to an external API.

Exit criteria:

- No raw command lines, script blocks, user paths, emails, secrets, or private
  values are sent by default.
- Payload size remains capped.
- AI provider failures do not block alerting or monitoring.
- Multiple AI providers can share the same compact, redacted analysis payload
  contract.

## Phase 8: Documentation, Testing, And CI

Documentation should be complete enough that a careful Windows user can install,
validate, operate, and remove Arcane EDR without prior project knowledge.

Required `v1.0.0` documentation:

- Step-by-step install guide using a release ZIP.
- Developer install guide using a source clone.
- Configuration reference for every supported config key.
- Alerting and notification sink guide.
- Modular AI analysis privacy guide.
- Sysmon setup guide.
- Admin-task elevation guide.
- Operations guide for start, stop, restart, validate, logs, daily summaries,
  and test alerts.
- Upgrade and rollback guide that explains config preservation.
- Troubleshooting guide for script policy, service install, missing emails,
  Sysmon, event log access, and noisy alerts.
- Release checklist that verifies the whole happy path:
  fresh install, validate config, optional Sysmon, install service, startup
  notification, test alert, daily summary, upgrade without wiping config, and
  clean uninstall.

- Add unit tests for:
  - config loading
  - CIDR parsing
  - command-line detection
  - baseline matching
  - persistence trust logic
  - alert sink routing
  - response mode gating
- Add GitHub Actions build.
- Add secret scanning guidance.
- Validate example config in CI.
- Build a release ZIP in CI or with a documented local script.

Exit criteria:

- A new user can install from a release ZIP using only
  `docs\step-by-step-install.md`.
- Each supported operational task has one documented command path.
- CI builds from a clean clone.
- Example configs validate.
- Local configs and runtime logs are not tracked.
- Core parsing and detection utilities have regression tests.

## Phase 9: Release Packaging

- Create release ZIP with:
  - `bin\ArcaneEDR.exe`
  - `config\*.example.config`
  - `config\arcaneedr-sysmon.xml`
  - `config\custom-rules.json`
  - `scripts`
  - `docs`
  - `README.md`
  - `LICENSE`
- Do not bundle Sysmon.
- Publish SHA256 checksum.
- Tag releases using semantic versioning.

Exit criteria for `v1.0.0`:

- Fresh install works from docs.
- Upgrade preserves local config.
- Baseline and alerting behavior are predictable.
- External notifications are modular.
- Agent-aware detections label and correlate known unattended agent behavior.
- Active response is dry-run or manual, auditable, and disabled by default.
- Privacy posture is documented and tested.
- The project remains useful without enterprise infrastructure or paid security
  platform dependencies.
