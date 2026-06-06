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
- `v0.4.0`: modular notification, reporting, response, and collector framework.
- `v0.5.0`: active response safety, rollback, and dry-run support.
- `v1.0.0`: documented stable release with tested install, upgrade, alerting,
  privacy, recovery behavior, and a clear mission as an agent-workstation safety
  layer.

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

Exit criteria:

- Normal workstation activity produces manageable log volume.
- Email and external alerts are actionable.
- Baseline learning can be disabled without causing a flood.
- High-confidence detections remain visible after local tuning.

## Phase 4: Modular Notification And Reporting

Brevo should be one notification sink, not the notification architecture.

- Add `CompositeAlertSink` to fan out to multiple alert sinks.
- Add per-sink enablement, minimum score, rate limiting, and failure isolation.
- Keep sink failures from blocking the core monitor loop or other sinks.
- Share alert formatting across sinks.
- Keep secrets in environment variables, Windows Credential Manager, or another
  secret provider, not in tracked config.

Candidate alert sinks:

- `BrevoEmailAlertSink`
- `SmtpEmailAlertSink`
- `WebhookAlertSink`
- `SlackAlertSink`
- `TeamsAlertSink`
- `DiscordAlertSink`
- `WindowsEventLogAlertSink`
- `SyslogAlertSink`
- `NtfyAlertSink`
- `PushoverAlertSink`

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

- Every active response is logged with rule, target, action, and result.
- Firewall blocks can be listed and rolled back.
- Trusted Windows, browser, Git, and development processes cannot be killed by
  broad rules.
- Active response can be tested safely in dry-run mode.

## Phase 7: Privacy And OpenAI

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

Exit criteria:

- No raw command lines, script blocks, user paths, emails, secrets, or private
  values are sent by default.
- Payload size remains capped.
- OpenAI failures do not block alerting or monitoring.

## Phase 8: Testing And CI

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
- Active response is safe, auditable, and disabled by default.
- Privacy posture is documented and tested.
- The project remains useful without enterprise infrastructure or paid security
  platform dependencies.
