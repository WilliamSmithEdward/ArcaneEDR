# Arcane EDR Rule Family Reference

This reference explains the current rule families at a practical level. It is
not a replacement for incident review. Use it to understand why an alert fired,
what telemetry is required, common false positives, and safe ways to test.

## Network Egress And Listeners

Rule IDs include `NET-EGRESS-*`, `NET-LISTEN-*`, `NET-INBOUND-*`,
`NET-C2-BEACON-PATTERN`, `NET-DIRECT-IP-WEB-EGRESS`, `NET-LATERAL-PORT`, and
`NET-DNS-UNAUTHORIZED-RESOLVER`.

- Detects: unexpected listeners, unusual outbound ports, direct-IP web egress,
  high-risk ports, external inbound connections, connection bursts, beacon-like
  timing, and unauthorized DNS resolver use.
- Required telemetry: netstat collection, with richer process context when WMI
  enrichment and Sysmon are available.
- Why it matters: RATs and loaders commonly need listener exposure, C2 egress,
  direct-IP callbacks, unusual ports, or repeated beaconing.
- Common false positives: development servers, browser extensions, update
  agents, VPNs, sync clients, package managers, and local test listeners.
- Tuning knobs: `AllowedListeningPorts`, `AllowedOutboundPorts`,
  `HighRiskRemotePorts`, `TrustedProcesses`, `AllowedRemoteCidrs`,
  `AllowedDnsResolvers`, `ConnectionBurstThreshold`, `BeaconMinimumSamples`,
  `BeaconMaxAverageIntervalSeconds`, and `BeaconMaxJitterRatio`.
- Safe test: `scripts\simulate-detection.cmd -Scenario UnexpectedListener`.
- Expected alert shape: `why` explains listener, egress, direct-IP, port, or
  beacon conditions; entity includes process and endpoint context when known.

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
  `TrustedPersistencePathIndicators`, `KnownRmmProcesses`,
  `UserWritablePathIndicators`, and baseline/reputation settings.
- Safe test: `scripts\simulate-detection.cmd -Scenario ScheduledTaskPersistence`
  followed by `scripts\simulate-detection.cmd -Scenario Cleanup`.
- Expected alert shape: `why` explains persistence telemetry; entity describes
  the service, scheduled task, startup item, registry item, or inventory record.

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
  network logons, and special-privilege logons.
- Required telemetry: Windows Security event log.
- Why it matters: unauthorized remote logons and privilege-bearing sessions are
  direct signs of hands-on access, brute force, password spraying, or lateral
  movement.
- Common false positives: expected RDP, mapped drives, local admin work,
  service accounts, and remote management tools.
- Tuning knobs: event log access, Windows auditing policy, and external alert
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
  `EnableReputationCache`, and `ReputationCacheFile`.
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

Rule IDs include `SERVICE-*`, `APP-*`, and `OPENAI-*`.

- Detects: service start/stop/recovery, daily summaries, config/executable
  integrity changes, and optional compact AI log analysis verdicts.
- Required telemetry: local health state, config integrity monitor, local logs,
  and optional AI analysis configuration.
- Why it matters: service recovery, monitor tampering, and AI-flagged patterns
  can explain why host monitoring changed or why multiple weak signals became
  alert-worthy.
- Common false positives: expected upgrades, publish/restart operations,
  validation tests, and manually requested OpenAI test analysis.
- Tuning knobs: `NotifyOnServiceStart`, `NotifyOnServiceStop`,
  `NotifyOnCrashRecovery`, `EnableDailySummary`, `EnableOpenAiLogAnalysis`,
  `OpenAIAnalysisScoreThreshold`, and `OpenAIAnalysisExcludedRuleIds`.
- Safe test: `ArcaneEDR.exe --test-health`, `ArcaneEDR.exe --test-alert`, and
  `ArcaneEDR.exe --test-openai-analysis` if configured.
- Expected alert shape: `why` explains service lifecycle, integrity, or compact
  AI analysis context.
