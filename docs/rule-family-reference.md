# Arcane EDR Rule Family Reference

This reference explains the current rule families at a practical level. It is
not a replacement for incident review. Use it to understand why an alert fired,
what telemetry is required, common false positives, and safe ways to test.

## Network Egress And Listeners

Rule IDs include `NET-EGRESS-*`, `NET-LISTEN-*`, `NET-INBOUND-*`,
`NET-C2-BEACON-PATTERN`, `NET-BEACON-TIMING-LOW-RISK`,
`NET-DIRECT-IP-WEB-EGRESS`, `NET-DIRECT-IP-WEB-EGRESS-SIGNED`,
`NET-EGRESS-TRUSTED-ALT-WEB-PORT`,
`NET-LAN-INBOUND-LATERAL-PORT`, `NET-LAN-EGRESS-LATERAL-PORT`,
`NET-LATERAL-PORT`, and `NET-DNS-UNAUTHORIZED-RESOLVER`.

- Detects: unexpected listeners, localhost-only listener noise, unusual
  outbound ports, direct-IP web egress, high-risk ports, external inbound
  connections, high-signal LAN inbound/egress to lateral-movement ports,
  connection bursts, beacon-like timing, and unauthorized DNS resolver use.
- Required telemetry: netstat collection, with richer process context when WMI
  enrichment and Sysmon are available.
- Why it matters: RATs and loaders commonly need listener exposure, C2 egress,
  direct-IP callbacks, unusual ports, or repeated beaconing.
- Common false positives: development servers, browser extensions, update
  agents, VPNs, sync clients, package managers, and local test listeners.
- Correlation-first tuning: timing-only beaconing and direct-IP HTTPS are
  reduced when the process is signed, expected, on a normal web port, outside
  user-writable paths, and lacks paired high-risk context such as suspicious
  command lines, LOLBins, RMM tools, persistence, risky ports, dynamic DNS, DoH
  bypass, blocked indicators, or suspicious parentage. Trusted signed processes
  using common alternate web/proxy ports such as `8080` or `8443` are also
  reduced to local context. The events remain logged locally as
  `NET-BEACON-TIMING-LOW-RISK`, `NET-DIRECT-IP-WEB-EGRESS-SIGNED`, or
  `NET-EGRESS-TRUSTED-ALT-WEB-PORT`.
- Duplicate reduction: the generic `NET-EGRESS-NEW-UNTRUSTED` context is not
  emitted when a more specific endpoint finding already explains the same
  connection, such as direct-IP web egress, DoH bypass, LOLBin/RMM egress,
  suspicious parentage, encoded command egress, or unsigned user-path egress.
- LAN classification: private-network sessions are not broadly alerted. Arcane
  raises `NET-LAN-INBOUND-LATERAL-PORT` when a private-network host connects to
  a local listener on configured lateral/admin ports, and
  `NET-LAN-EGRESS-LATERAL-PORT` when an untrusted process connects outbound to
  those ports on a private-network host.
- Tuning knobs: `AllowedListeningPorts`, `AllowedOutboundPorts`,
  `ProcessAllowedOutboundPorts`, `HighRiskRemotePorts`, `TrustedProcesses`,
  `AllowedRemoteCidrs`, `AllowedDnsResolvers`, `ConnectionBurstThreshold`,
  `BeaconMinimumSamples`, `BeaconMaxAverageIntervalSeconds`,
  `BeaconMaxJitterRatio`, and low-value repeat dampening settings.
  `ProcessAllowedOutboundPorts` is useful when a specific trusted process has a
  normal nonstandard destination port that should not make that port globally
  normal for every process.
- Safe test: `scripts\simulate-detection.cmd -Scenario UnexpectedListener`.
  This opens a localhost-only TCP listener and should produce
  `NET-LISTEN-TCP-LOCALHOST-UNEXPECTED`.
- Expected alert shape: `why` explains listener, localhost-only listener,
  egress, direct-IP, port, or beacon conditions; entity includes process and
  endpoint context when known.

## PowerShell And Encoded Commands

Rule IDs include `PS-*`, `PROC-ENCODED-CLI`, `AUDIT-PROC-ENCODED-CLI`, and
`RAT-ENCODED-CLI-EGRESS`.

- Detects: encoded or base64-like command content, suspicious PowerShell terms,
  stealth/download combinations, Defender tampering terms, and persistence
  command terms.
- Required telemetry: PowerShell Operational log, Windows process-creation audit
  events, or Sysmon process creation events.
- Why it matters: encoded and stealthy PowerShell remains common in loader,
  RAT staging, and post-exploitation chains.
- Common false positives: administrative scripts, installers, endpoint tools,
  configuration management, and test harnesses.
- Parent/source context: PowerShell Operational events include host process and
  parent process context when the process is still observable at collection
  time.
- App inventory carveout: `PS-ENCODED-APP-INVENTORY` records encoded
  Start-app/process/UserAssist inventory as medium severity instead of the
  critical generic encoded-command rule.
- Encoded switch precision: ordinary PowerShell parameters such as
  `-Encoding` and .NET `System.Text.Encoding` references are not treated as
  encoded-command execution; the encoded-command switch matcher looks for
  bounded `-enc`, `-EncodedCommand`, or `/EncodedCommand` forms.
- Release packaging scaffolding: Arcane's own package-release compression
  assembly loading is ignored as benign PowerShell scaffolding, while unrelated
  download, encoded, persistence, or tamper patterns remain alertable.
- Tuning knobs: `DetectEncodedCommandLines`, `EncodedCommandMinimumLength`, and
  `SuspiciousCommandLineTerms`.
- Safe test: `scripts\simulate-detection.cmd -Scenario EncodedPowerShell`.
- Expected alert shape: `why` explains encoded command, PowerShell telemetry, or
  process-audit command-line indicators.

## Persistence

Rule IDs include `PERSIST-*`.

- Detects: service installs, scheduled-task creates/updates, first-seen
  persistence inventory items, suspicious persistence paths, LOLBin references,
  encoded command text, and RMM/RAT-like tooling names.
- Required telemetry: Windows Security/System event logs and persistence
  inventory collection.
- Why it matters: unauthorized services, scheduled tasks, Run keys, and startup
  entries are common RAT persistence mechanisms.
- Common false positives: software installers, driver updates, Windows feature
  tasks, legitimate remote-support tools, and expected admin maintenance.
- Tuning knobs: `TrustedPersistenceNamePrefixes`,
  `TrustedPersistencePathIndicators`, `TrustedPersistenceSignerSubjects`,
  `KnownRmmProcesses`, `UserWritablePathIndicators`, and baseline/reputation
  settings.
- Trust handling: service and scheduled-task changes can be classified as
  trusted-location variants only when configured trusted name indicators match
  a trusted path or trusted signer, and suspicious command, untrusted
  user-writable path, and RMM/RAT-like traits are absent. Microsoft-looking
  names alone are not trusted.
- Safe test: `scripts\simulate-detection.cmd -Scenario ScheduledTaskPersistence`
  followed by `scripts\simulate-detection.cmd -Scenario Cleanup`.
- Expected alert shape: `why` explains persistence telemetry; entity describes
  the service, scheduled task, startup item, registry item, or inventory record.

## File Create Guardrails

Rule IDs include `FILE-HIGH-RISK-EXECUTABLE-DROP`,
`FILE-HIGH-RISK-DROP-SUSPICIOUS-WRITER`,
`FILE-AGENT-EXECUTABLE-DROP-OUTSIDE-ROOT`,
`FILE-SENSITIVE-MATERIAL-TOUCHED`, and `FILE-DROP-THEN-EXECUTION`.

- Detects: executable or script drops into persistence-adjacent or extension
  locations, suspicious writers touching sensitive-looking filenames, configured
  agent tools writing executable/script files outside approved roots, and recent
  high-risk file drops followed by execution.
- Required telemetry: Sysmon FileCreate event 11 using the bundled narrow
  Sysmon config or an equivalent local Sysmon policy.
- Why it matters: many loader and RAT chains create scripts, shortcuts,
  binaries, browser-extension payloads, credentials, or startup artifacts before
  execution or persistence becomes obvious.
- Common false positives: installers, browser extension updates, admin scripts,
  package-manager work outside configured roots, and intentional simulations.
- Tuning knobs: `EnableHighSignalFileDetection`,
  `HighRiskFilePathIndicators`, `HighRiskFileExtensions`,
  `SensitiveFileNameIndicators`, `AgentWorkspaceRoots`, `AgentPublishRoots`,
  `AgentProcessNames`, `AgentChildProcessNames`,
  `AgentPackageManagerProcesses`, `TrustedProcesses`, and
  `SuspiciousCommandLineTerms`.
- Scope boundary: Arcane does not broadly audit file changes. It relies on
  Sysmon emitting a narrow set of high-risk FileCreate events and then requires
  path, extension, writer, agent-root, sensitive-name, or execution correlation.
- Safe test: `scripts\simulate-detection.cmd -Scenario StartupFileDrop`
  followed by `scripts\simulate-detection.cmd -Scenario Cleanup`.
- Expected alert shape: `why` explains file-create telemetry; entity includes
  writer process, parent process when available, signer/hash context, user, and
  target filename.

## Process Reputation And LOLBins

Rule IDs include `PROC-*`, `REPUTATION-*`, and `RAT-LOLBIN-*`.

- Detects: first-seen executable paths/hashes, unsigned user-writable egress,
  suspicious parent chains, blocked process hashes, LOLBins with suspicious
  command lines, and newly observed RMM/RAT-like process names.
- Required telemetry: Sysmon process events and WMI process enrichment.
- Why it matters: many compromises execute from user-writable locations, abuse
  signed Windows utilities, or introduce new remote-management binaries.
- Common false positives: development builds, portable tools, package-manager
  shims, installers, and legitimate support software.
- Tuning knobs: `TrustedProcesses`, `LolbinProcesses`, `KnownRmmProcesses`,
  `SuspiciousParentProcesses`, `UserWritablePathIndicators`,
  `EnableReputationCache`, and `ReputationCacheFile`.
- Safe test: use the encoded PowerShell simulation for command-line coverage;
  no generic unsigned-binary test is included yet.
- Expected alert shape: `why` explains process creation, LOLBin, reputation,
  hash, path, parent, or network traits.

## Agent Guardrails

Rule IDs include `AGENT-ADMIN-COMMAND`, `AGENT-SECRET-REFERENCE`, and
`AGENT-SUPPLY-CHAIN-COMMAND`.

- Detects: configured unattended-agent context invoking elevation, scheduled
  task, service, firewall, ACL, registry persistence, or security-control
  commands outside configured approved admin tasks; configured secret, token,
  SSH key, certificate, cloud credential, or browser credential-store
  references; and package installs, source clones, downloads, install scripts,
  or expression-execution indicators launched from agent-adjacent telemetry.
- Required telemetry: PowerShell Operational log, Windows process-creation
  audit events, or Sysmon process creation events, plus `AgentProfile` config.
- Why it matters: unattended coding agents often need broad local tools, so
  unexpected machine-control, credential-adjacent, and supply-chain-adjacent
  commands should be visible even when the command is not independently
  malicious.
- Common false positives: approved publish/restart work, install scripts,
  package-manager postinstall hooks, admin validation, and intentional local
  maintenance.
- Tuning knobs: `EnableAgentProfile`, `AgentProcessNames`,
  `AgentChildProcessNames`, `AgentWorkspaceRoots`, `AgentPublishRoots`,
  `AgentApprovedAdminTaskNames`, `EnableAgentAdminCommandGuardrails`,
  `AgentAdminCommandMinimumScore`, `AgentAdminCommandTerms`,
  `EnableAgentSecretReferenceGuardrails`,
  `AgentSecretReferenceMinimumScore`, `AgentSecretReferenceTerms`,
  `EnableAgentSupplyChainGuardrails`, `AgentSupplyChainMinimumScore`,
  `AgentSupplyChainTerms`, maintenance context term groups, and bounded
  maintenance session markers.
- Scope boundary: this is alert-only evidence. It does not change
  `ResponseMode`, add firewall blocks, terminate processes, or suppress local
  logs.
- Safe test: run an approved admin task through
  `scripts\run-admin-task.cmd ValidateAdmin` and confirm it is labeled as
  expected context; test unapproved commands only in a disposable lab.
- Expected alert shape: `why` explains configured agent context; body includes
  `CommandFamily`, `SecretReferenceFamily`, or `SupplyChainFamily`, matched
  term, source telemetry, and `ResponseMode=AlertOnly`.

## Response Follow-Up

Rule IDs include `RESPONSE-*`, currently `RESPONSE-PROCESS-RESPAWN`.

- Detects: a same-named process launching shortly after Arcane successfully
  recorded an active process-termination response for that process.
- Required telemetry: response ledger plus Sysmon process creation events.
- Why it matters: process respawn after termination can indicate service
  recovery, a supervisor, persistence, or resilient malware behavior.
- Common false positives: expected services, watchdogs, updaters, shells, and
  intentionally restarted tools.
- Tuning knobs: `EnableResponseFollowUpDetections`,
  `ResponseProcessRespawnWindowMinutes`, `ResponseProcessRespawnMinimumScore`,
  `ResponseFollowUpExternalAlertMinimumScore`, response ledger settings, and
  detection policy.
- Flood protection: response follow-up alerts use a separate external alert
  threshold so local evidence is preserved without creating repeated email or
  webhook notifications by default.
- Expected alert shape: `why` explains response follow-up context; body includes
  response ID, triggering rule, process name, and respawn window.

## DNS And Domain Signals

Rule IDs include `DNS-*` and `DNS-DOH-*`.

- Detects: blocked domain matches, dynamic DNS providers, high-entropy DNS
  labels, untrusted process DoH use, and unauthorized DNS resolver connections.
- Required telemetry: Sysmon DNS events, endpoint network telemetry, and
  configured domain/CIDR indicators.
- Why it matters: RATs frequently use disposable dynamic DNS, DoH, direct DNS
  policy bypass, or generated-looking hostnames.
- Common false positives: CDNs, tracking domains, browser behavior, security
  tools, VPNs, and privacy-focused DNS software.
- Tuning knobs: `BlockedDomains`, `DynamicDnsSuffixes`, `DohProviderCidrs`,
  `AllowedDnsResolvers`, `EnforceAuthorizedDnsResolvers`, and
  `TrustedProcesses`.
- Safe test: no DNS simulation is included yet; use custom rules or a lab-only
  blocked test domain if needed.
- Expected alert shape: `why` explains DNS indicator, high-entropy, DoH, or
  resolver conditions.

## Authentication

Rule IDs include `AUTH-*`.

- Detects: remote failed logons, repeated failed remote logons, RDP logons,
  network logons, unspecified-source remote-style logons, standalone
  special-privilege logons, and special privileges that correlate with recent
  remote access.
- Required telemetry: Windows Security event log.
- Why it matters: unauthorized remote logons and privilege-bearing sessions are
  direct signs of hands-on access, brute force, password spraying, or lateral
  movement.
- Common false positives: expected RDP, Hyper-V enhanced sessions or local
  session brokering that reports `0.0.0.0`, mapped drives, local admin work,
  service accounts, and remote management tools.
- Correlation-first tuning: standalone `4672` special-privilege events are
  low-severity local context and repeat-dampened per principal. If special
  privileges arrive shortly after remote logon activity for the same account,
  Arcane raises `AUTH-REMOTE-SPECIAL-PRIVILEGES` as stronger context.
- Tuning knobs: event log access, Windows auditing policy,
  `AuthSpecialPrivilegeRepeatDampeningMinutes`,
  `AuthSpecialPrivilegeRemoteCorrelationMinutes`, and external alert
  suppression groups for known maintenance windows.
- Safe test: no authentication simulation is included because it can affect
  account/security policy.
- Expected alert shape: `why` explains remote logon, failed logon, or privileged
  logon telemetry.

## Baseline And Reputation Novelty

Rule IDs include `BASELINE-*` and `REPUTATION-*`.

- Detects: process/domain pairs, process/destination pairs, processes, and
  persistence items not previously observed in local state.
- Required telemetry: baseline store, reputation cache, DNS/network/process
  events, and warmup state.
- Why it matters: novelty is weak alone, but useful when paired with suspicious
  process lineage, unusual egress, encoded commands, or persistence.
- Common false positives: normal first-run behavior, updates, new projects,
  newly installed tools, and browser/package-manager churn.
- Tuning knobs: `BaselineEnabled`, `BaselineLearningMode`,
  `BaselineWarmupHours`, `BaselineLearningEmailMinimumScore`,
  `EnableReputationCache`, `ReputationCacheFile`, and low-value repeat
  dampening settings.
- Safe test: run during a lab baseline transition; no standalone simulation is
  included because novelty depends on local state.
- Expected alert shape: `why` explains local baseline or reputation novelty.

## Indicators And Custom Rules

Rule IDs include `*-IOC-*`, `CUSTOM-*`, and configured custom rule IDs.

- Detects: blocked IPs/CIDRs, blocked hashes, blocked domains, and local JSON
  custom rule matches.
- Required telemetry: the relevant network, DNS, process, PowerShell, Windows
  event, or persistence collector plus configured indicators/rules.
- Why it matters: configured indicators represent operator intent and should be
  higher-confidence than generic heuristic signals.
- Common false positives: stale indicators, shared infrastructure, or broad
  custom terms.
- Tuning knobs: `BlockedDomains`, `BlockedHashes`, `BlockedRemoteCidrs`,
  `EnableCustomRules`, and `CustomRulesFile`.
- Safe test: add a temporary lab-only custom rule, then remove it.
- Expected alert shape: `why` explains indicator or custom-rule matching.

## Service, Health, Integrity, And AI Analysis

Rule IDs include `SERVICE-*`, `APP-*`, and `AI-*`.

- Detects: service start/stop/recovery, daily reports, config/executable
  integrity changes, optional compact AI log analysis verdicts, and optional
  AI daily report analysis.
- Required telemetry: local health state, config integrity monitor, local logs,
  and optional AI analysis configuration.
- Why it matters: service recovery, monitor tampering, and AI-flagged patterns
  can explain why host monitoring changed or why multiple weak signals became
  alert-worthy.
- Common false positives: expected upgrades, publish/restart operations,
  validation tests, and manually requested AI test analysis.
- Tuning knobs: `NotifyOnServiceStart`, `NotifyOnServiceStop`,
  `NotifyOnCrashRecovery`, `EnableDailySummary`,
  `EnableDailySummaryAIAnalysis`, `EnableAIAnalysis`,
  `AIAnalysisScoreThreshold`, and `AIAnalysisExcludedRuleIds`.
- Safe test: `ArcaneEDR.exe --test-health`, `ArcaneEDR.exe --test-alert`,
  `ArcaneEDR.exe --test-daily-report`, `ArcaneEDR.exe --preview-daily-report`,
  and `ArcaneEDR.exe --test-ai-analysis` if configured.
- Expected alert shape: `why` explains service lifecycle, integrity, compact AI
  analysis context, or daily report generation. Daily reports use a dedicated
  report layout with near-top critical-priority local signal callouts rather
  than the generic alert email template.
