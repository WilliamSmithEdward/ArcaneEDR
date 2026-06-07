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
  install, logging, Brevo alerting, Sysmon ingestion, OpenAI compact analysis,
  baseline learning, and daily summaries.
- `v0.2.0`: install, upgrade, validation, and packaging hardening.
- `v0.3.0`: detection quality, false-positive reduction, and per-rule tuning.
- `v0.4.0`: modular notification and reporting framework.
- `v0.5.0`: investigation MVP, rule explanations, and safe simulations.
- `v0.6.0`: agentic workstation guardrails MVP and active-response dry-run.
- `v0.7.0`: collector/rule interface cleanup and privacy hardening.
- `v1.0.0`: documented stable release with tested install, upgrade, alerting,
  privacy, recovery behavior, and a clear mission as an agent-workstation safety
  layer.

## Milestone Execution Policy

Work should finish the active milestone before moving to the next milestone
whenever that is practical. A later milestone may be touched early only when it
unblocks the active milestone, prevents avoidable rework, fixes an urgent
operational issue, or is a very small adjacent change with low risk.

Current active milestone: `v0.3.0`.

Definition of done before moving focus to `v0.4.0`:

- Per-rule enable/disable and per-rule external alert thresholds exist.
- Rule categories are assigned consistently and included in alert metadata.
- Maintenance/session labeling or suppression covers expected build, publish,
  install, validation, and admin-bridge workflows without hiding unrelated
  suspicious behavior.
- Microsoft-signed scheduled-task and service trust handling is improved enough
  to reduce known Windows noise.
- Alert-volume tuning produces manageable local and external alert volume.
- Remaining `v0.3.0` gaps are either completed or explicitly deferred with a
  reason.

## Milestone Status

This section is the high-level completion tracker. Detailed work remains in the
phase sections below.

| Milestone | Status | Completion | Notes |
| --- | --- | --- | --- |
| `v0.1.x-preview` | Done | Complete | Functional preview: service, local logging, Brevo alerting, Sysmon ingestion, OpenAI compact analysis, baseline learning, and daily summaries. |
| `v0.2.0-beta` | Done | Complete | Tagged beta with install, upgrade, validation, package-release script, config preservation, and scheduled-task admin bridge. |
| `v0.3.0` | In progress | Partial | Rule categories and rule-policy tuning are in progress. Remaining detection quality work includes maintenance labeling, better trust handling, and alert-volume tuning. |
| `v0.4.0` | Mostly done | Substantial | Modular alert sinks are implemented for Brevo, SMTP, webhook, generic HTTP/API, Windows Event Log, and local JSONL. Reporting-specific sinks remain future work. |
| `v0.5.0` | Mostly done | Substantial | `why` explanations, incident grouping, timeline command, support bundle, simulations, and rule-family docs are implemented. Remaining work is polishing expected alert shapes and demo flow. |
| `v0.6.0` | Started | Partial | Agent Profile labeling exists. Remaining work includes agent write/elevation guardrails, compact activity ledger, maintenance/session markers, and active-response dry-run. |
| `v0.7.0` | Not started | Planned | Collector/rule interface cleanup, privacy hardening, and AI provider abstraction remain planned. |
| `v1.0.0` | Not ready | Planned | Requires completed docs, tuned alert volume, tested install/upgrade/release flow, dry-run/manual response safety, and stable privacy/operations posture. |

Current milestone focus: finish `v0.3.0` detection quality and alert-volume
tuning, then move into `v0.4.0` modular notification/reporting polish.

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
- OpenAI compact analysis does not alert on ordinary baseline noise.

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
  `Sysmon`, `OpenAI`, and `Health`.
- Improve Microsoft-signed scheduled-task and service trust handling.
- Add explicit maintenance-mode suppression for expected build, publish,
  install, and validation commands.
- Reduce repeated low-value alerts from the same stable process and behavior.
- Improve localhost-only listener classification.
- Keep high and critical alerts rare and actionable.

Progress:

- Added central rule categories derived from rule IDs and included category in
  alert JSON, email/plain-text formatting, Windows Event Log alerts, local
  logs, retry queue state, incident records, and support-bundle summaries.
- Added config-driven rule policy:
  - `DisabledRuleIds`
  - `DisabledRuleCategories`
  - `RuleMinimumEmailScores`
  - `CategoryMinimumEmailScores`

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

Reporting should be separate from alerting where useful:

- Daily summary report sink.
- Markdown or JSON report sink.
- Webhook report sink.
- Local report archive.

Exit criteria:

- Multiple sinks can be enabled at once.
- One failed sink does not prevent another sink from receiving an alert.
- Brevo-specific settings are isolated to the Brevo sink.

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

Exit criteria:

- Collectors are independently enableable and fail-isolated.
- Rules have IDs, categories, defaults, tests, and per-rule config.
- Optional enrichment can be added without changing detection flow broadly.

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
- De-duplicate firewall rules.
- Maintain a response ledger for rollback.
- Add commands to list and remove Arcane EDR firewall blocks.
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

- Keep OpenAI analysis optional and disabled in example config.
- Keep payloads compact, bounded, and redacted.
- Add a command that previews exactly what would be sent.
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

- Introduce an `IAiAnalysisProvider` abstraction so OpenAI is one provider, not
  the analysis architecture.
- Keep OpenAI as the first supported provider.
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
- OpenAI and modular AI analysis privacy guide.
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
