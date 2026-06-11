# Arcane EDR

<p align="center">
  <img src="src/Assets/square_logo.png" alt="Arcane EDR logo" width="280">
</p>

Arcane EDR is a lightweight Windows service for making unattended agent
workstations safer while still allowing fast, bleeding-edge work. It is built
for sandbox hosts, AI-agent boxes, and small environments where autonomous tools
need broad local capability, but the owner still wants guardrails against
supply-chain compromise, RAT-like activity, persistence, suspicious egress, and
credential or remote-access abuse.

It watches TCP/UDP activity, enriches events with local process and host
context, scores suspicious behavior, writes local evidence, and can send
qualified alerts through modular notification paths. The goal is practical
host-level safety without needing to set up or pay for a full enterprise EDR,
SIEM, MDM, or SOC deployment.

The project intentionally uses .NET Framework and built-in Windows components
only, so it can be built on a Windows host without downloading NuGet packages.

See [docs/project-mission.md](docs/project-mission.md) for the project mission.
See [docs/release-deployment-policy.md](docs/release-deployment-policy.md) for
the source-vs-live deployment policy.
If you are using an LLM or coding agent to operate the repo, see
[AGENTS.md](AGENTS.md) for agent-specific workflow and tuning instructions.

## What It Detects

- New listening TCP/UDP ports.
- New external outbound TCP connections.
- External inbound TCP connections.
- Connections to commonly abused remote ports.
- Connection bursts by process.
- Low-jitter repeated outbound connections that resemble beaconing.
- Process path, command line, parent process, user, signer, and SHA256 context.
- Sysmon process, network, DNS, and narrow high-risk file-create events when Sysmon is installed.
- PowerShell operational log events, including script block, module, and lifecycle records.
- Windows Security/System events for failed logons, RDP/network logons, privileged logons, service installs, scheduled task changes, and process-creation audit events when enabled.
- Registry Run keys, Startup folders, automatic services, and scheduled-task inventory.
- Executable/script drops into persistence-adjacent locations, suspicious sensitive-file writes, and high-risk file drop-then-execute patterns.
- LOLBin and script-runtime external network activity.
- Encoded or base64-obfuscated PowerShell/CLI commands.
- Suspicious parent/child process chains.
- Unsigned executables launched from user-writable paths.
- First-seen executable and persistence reputation cache.
- Local JSON custom rules in `config\custom-rules.json`.
- Known RMM/RAT process names.
- Blocked domains, hashes, IPs, and CIDRs.
- High-entropy DNS and dynamic DNS providers.
- Optional DNS-over-HTTPS resolver detection.
- Optional DNS resolver enforcement.
- Untrusted process connections to internal lateral-movement ports.

Arcane EDR is not a packet sniffer or a full EDR platform. It is a focused
Windows safety layer intended for unattended agent workstations, sandbox hosts,
and small environments where local visibility and simple alerting are useful.

See [ROADMAP.md](ROADMAP.md) for the beta-to-`v1.0.0` roadmap.
See [docs/rule-family-reference.md](docs/rule-family-reference.md) for a
practical guide to current rule families, telemetry requirements, tuning knobs,
false positives, and safe tests.

## Requirements

- Windows with .NET Framework compiler available at
  `%WINDIR%\Microsoft.NET\Framework64\v4.0.30319\csc.exe` or the 32-bit
  Framework path.
- PowerShell.
- Administrator rights for service install, service removal, Sysmon install,
  and some event-log validation checks.
- Optional: Sysmon for richer process, network, DNS, and narrow file-create telemetry.
- Optional: Brevo transactional email for external alert delivery.
- Optional: AI provider API key for compact secondary log analysis.

## Quick Start

For a release-ZIP install with every step spelled out, start with
[docs/step-by-step-install.md](docs/step-by-step-install.md).

Clone the repo and create local config files from the tracked templates:

```powershell
git clone https://github.com/WilliamSmithEdward/ArcaneEDR.git
cd ArcaneEDR
Copy-Item .\config\ArcaneEDR.example.config .\config\ArcaneEDR.config
Copy-Item .\config\Deployment.example.config .\config\Deployment.config
```

Build the executable:

```powershell
.\scripts\build.ps1
```

Run in console mode:

```powershell
.\bin\ArcaneEDR.exe --console
```

Validate configuration and host prerequisites:

```powershell
.\bin\ArcaneEDR.exe --validate-config
```

Validate a specific config file while tuning a clone or staged deployment:

```powershell
.\bin\ArcaneEDR.exe --validate-config .\config\ArcaneEDR.config
```

Print the executable version:

```powershell
.\bin\ArcaneEDR.exe --version
```

## Configuration

Tracked template files are safe defaults for GitHub:

- `config\ArcaneEDR.example.config`: runtime identity, log directory, alert
  settings, event log names, thresholds, schedules, and detection tuning.
- `config\Deployment.example.config`: publish destination, application folder,
  executable name, Sysmon executable name, and Sysmon config filename.

Local files are intentionally ignored by Git:

- `config\ArcaneEDR.config`
- `config\Deployment.config`
- `config\arcane-policy.json`

Keep machine-specific values, recipient addresses, local paths, and environment
variable names in the ignored local files. The example runtime config disables
external alerting and AI analysis by default.

## Project Layout

- `src\Collection`: captures netstat, Sysmon, PowerShell, Windows Event Log, and persistence telemetry.
- `src\Enrichment`: adds process path, command line, parent, hash, signer, and user context.
- `src\Detection`: applies traffic, host, process, DNS, reputation, custom, baseline, and RAT-oriented rules.
- `src\Alerting`: handles alert cooldowns and provider-specific delivery sinks.
- `src\Response`: optional firewall block and process termination actions.
- `src\Runtime`: service polling, health, and integrity checks.
- `src\Configuration`: loads allowlists, thresholds, alert settings, and rule options.
- `src\Logging`: writes text logs and JSONL alert records with rotation.
- `src\Models`: shared alert, process, DNS, and network endpoint models.
- `src\Utils`: CIDR, IP, domain, filesystem, and port-range helpers.
- `src\Validation`: offline configuration and environment checks.
- `scripts`: build, publish, service install, service removal, and Sysmon install helpers.

## Build And Publish

Source work is separate from live deployment. Ordinary source and documentation
changes should be built and validated from the source folder, but not published
to the live application folder unless a tagged release is being deployed or the
operator explicitly asks for a live update. See
[docs/release-deployment-policy.md](docs/release-deployment-policy.md).

Build:

```powershell
.\scripts\build.ps1
```

Publish to the destination configured in local `config\Deployment.config`, or
the example deployment config when no local config exists:

```powershell
.\scripts\publish.ps1
```

The published folder contains the executable, config files, docs, Sysmon config,
and install scripts. If a published `config\ArcaneEDR.config` already exists,
publish preserves it and writes the source config as
`config\ArcaneEDR.example.config`. Use `-OverwriteConfig` only when replacing a
live runtime config is intentional.

Existing published `config\Deployment.config` is also preserved by default. Use
`-OverwriteDeploymentConfig` only when replacing the live deployment config is
intentional.

Create a release ZIP from tracked templates, scripts, docs, and build output:

```powershell
.\scripts\package-release.ps1
```

The release ZIP is written under `artifacts` with a SHA256 checksum file. Local
machine configs, runtime logs, and Sysmon binaries are not included.

## Install As A Windows Service

Run PowerShell as Administrator from the published application folder:

```powershell
.\scripts\install-service.ps1
```

The service is installed using `ServiceName`, `ServiceDisplayName`, and
`ServiceDescription` from `config\ArcaneEDR.config`.

Uninstall:

```powershell
.\scripts\uninstall-service.ps1
```

The installer configures Windows Service Control Manager recovery actions:

- restart after 60 seconds on first failure
- restart after 60 seconds on second failure
- restart after 5 minutes on subsequent failure
- reset the failure counter after 24 hours

## Optional Constrained Admin Tasks

If you do not want to run the Codex desktop app as Administrator, you can create
on-demand scheduled tasks for specific elevated maintenance operations. This is
more constrained than giving a tool a general admin shell.

This is the preferred elevation strategy for Arcane EDR maintenance from Codex.
See `docs\elevation-strategy.md` for the operating model.

Run once from an elevated PowerShell session in the source repo:

```powershell
cd C:\Development\ArcaneEDR
.\scripts\install-admin-tasks.cmd
```

This registers these on-demand tasks under `\ArcaneEDR\`:

- `PublishRestart`: stop service if installed, build from source, publish while
  preserving live config, then restart the service.
- `InstallService`: publish, install the Windows service, configure service
  recovery, then start it.
- `UninstallService`: stop and remove the Windows service.
- `InstallSysmon`: install or update Sysmon from the published `tools` folder.
- `ValidateAdmin`: run `ArcaneEDR.exe --validate-config` elevated.

After setup, a normal shell can trigger an approved task:

```powershell
.\scripts\run-admin-task.cmd -TaskName PublishRestart
.\scripts\run-admin-task.cmd -TaskName ValidateAdmin
```

The `.cmd` wrappers use `powershell.exe -ExecutionPolicy Bypass -File` so the
workflow still works on machines where local `.ps1` execution is restricted.

Task output is written to:

```text
C:\Security\AdminTasks\<TaskName>.log
```

Remove the tasks from an elevated PowerShell session:

```powershell
.\scripts\uninstall-admin-tasks.cmd
```

## Optional Sysmon

Arcane EDR can read Sysmon when Sysmon is already installed on the machine. If
the `SysmonServiceName` from `config\ArcaneEDR.config` is running, no Sysmon
binary is needed in the Arcane EDR folder.

The `tools` folder is only for installing or updating Sysmon from the published
app folder. Sysmon is not bundled. To use that workflow, download Sysmon from
Microsoft Sysinternals, place the executable named by `SysmonExecutableName` in
`tools`, then run:

```powershell
.\scripts\install-sysmon.cmd
```

The included `config\arcaneedr-sysmon.xml` enables process creation, network
connection, DNS query, SHA256 hash telemetry, and narrow FileCreate coverage for
Startup folders, scheduled-task storage, browser extension paths, and
sensitive-looking filenames. If Sysmon is not installed, Arcane EDR falls back
to netstat-based collection and logs a warning once.

## Test Commands

Test alert delivery:

```powershell
.\bin\ArcaneEDR.exe --test-alert
.\bin\ArcaneEDR.exe --test-alert --count 2
```

Test service-health notification delivery:

```powershell
.\bin\ArcaneEDR.exe --test-health
```

Force compact AI log analysis:

```powershell
.\bin\ArcaneEDR.exe --test-ai-analysis
```

Generate and send a daily report on demand:

```powershell
.\bin\ArcaneEDR.exe --test-daily-report
```

Preview a daily report without sending an external notification or making an
AI API call:

```powershell
.\bin\ArcaneEDR.exe --preview-daily-report
.\bin\ArcaneEDR.exe --preview-daily-report --json
.\bin\ArcaneEDR.exe --preview-daily-report --archive
```

Use `--validate-config <config-path>` to check a staged report configuration
without copying it into the runtime `config` directory first.

Preview the exact redacted payload that would be sent to the AI provider without
making an API call:

```powershell
.\bin\ArcaneEDR.exe --preview-ai-payload
```

Generate a privacy-first local support bundle:

```powershell
.\bin\ArcaneEDR.exe --support-bundle
```

The bundle is written under `LogDirectory` and includes version, redacted
config, service health state, collector/sink/runtime checks, recent alert
summaries, recent warning/error lines, recent incident summaries, and active
external sink/AI provider metadata. It does not copy raw alert bodies, entities,
command lines, script blocks, AI payloads, or secret values.

Preview structured detection policy effects against recent alerts:

```powershell
.\bin\ArcaneEDR.exe --policy-preview --last 24h --limit 20
```

Run one monitor poll and exit without starting the Windows service or writing
service lifecycle health state:

```powershell
.\bin\ArcaneEDR.exe --poll-once
```

List safe detection simulations:

```powershell
.\scripts\simulate-detection.cmd -Scenario List
```

Run one representative simulation:

```powershell
.\scripts\simulate-detection.cmd -Scenario EncodedPowerShell
.\scripts\simulate-detection.cmd -Scenario UnexpectedListener -DurationSeconds 120
.\scripts\simulate-detection.cmd -Scenario ScheduledTaskPersistence
.\scripts\simulate-detection.cmd -Scenario StartupFileDrop
```

Run a compact demo path that cleans prior simulation artifacts, generates
harmless suspicious process telemetry, opens a localhost listener long enough
for the service or a second-shell poll, and prints the review commands:

```powershell
.\scripts\simulate-detection.cmd -Scenario Demo -DurationSeconds 120
```

Clean up the scheduled-task simulation artifact:

```powershell
.\scripts\simulate-detection.cmd -Scenario Cleanup
```

These simulations are harmless, but they can generate real local alerts and
external notifications when the service is running. The unexpected-listener
simulation binds to localhost and should produce the lower-severity
`NET-LISTEN-TCP-LOCALHOST-UNEXPECTED` shape in current builds.

## Alerting

All alerts are always written locally under `LogDirectory`:

```text
<LogDirectory>\ArcaneEDR.log
<LogDirectory>\ArcaneAlerts.jsonl
```

Every alert carries structured `why` metadata that explains the rule-family
conditions that caused it to fire. Alert records include UTC time plus the
machine's system-local time, Windows time zone, and UTC offset. Email, SMTP,
Windows Event Log, local text logs, local JSONL, webhook, and generic HTTP/API
sinks all receive the same explained, time-zone-aware alert object.

System-local time is derived from the Windows time zone configured on the host.
This avoids hard-coding a project timezone while keeping alerts and reports
readable for the operator.

Alerts also carry a rule `category`, derived from the rule ID. Current
categories include `Network`, `DNS`, `PowerShell`, `Persistence`, `Auth`,
`File`, `Process`, `Agent`, `Response`, `RAT`, `AI`, `Health`, `Integrity`,
`Baseline`, `Reputation`, `Custom`, `Test`, and `General`.

Arcane persists Windows, PowerShell, and Sysmon event-log watermarks under
`LogDirectory` by default:

```ini
PersistEventLogWatermarks=true
EventLogWatermarkFile=ArcaneEventLogWatermarks.tsv
```

Collector toggles are independent, and bounded collector, analysis-stage, or
per-alert dispatch failures are logged without stopping the rest of the poll:

```ini
EnableNetstatCollector=true
EnableSysmonIngestion=true
EnablePowerShellLogIngestion=true
EnableWindowsEventIngestion=true
EnablePersistenceInventory=true
```

This prevents service restarts, publish cycles, and recovery restarts from
reprocessing the same recent event records into new local alerts and daily
report counts. If an event log appears to have reset or been cleared, Arcane
allows newer low-record-ID events through instead of permanently trusting the
older watermark.

Rule policy tuning is controlled by config:

```ini
DisabledRuleIds=
DisabledRuleCategories=
RuleMinimumEmailScores=NET-DIRECT-IP-WEB-EGRESS=90,NET-EGRESS-UNUSUAL-PORT=90,NET-EGRESS-NEW-UNTRUSTED=80,NET-BEACON-TIMING-LOW-RISK=90,PS-SUSPICIOUS-COMMAND=90,BASELINE-NEW-PROCESS-DOMAIN=95,BASELINE-NEW-PROCESS-DESTINATION=95
CategoryMinimumEmailScores=
```

`DisabledRuleIds` and `DisabledRuleCategories` suppress matching alerts before
local alert logging, incident grouping, response handling, and external
delivery. `RuleMinimumEmailScores` and `CategoryMinimumEmailScores` affect
external delivery only; local logging and incident grouping still use the
normal alert path. The example `RuleMinimumEmailScores` profile keeps weak
standalone discovery signals mostly local by default; use `--alert-volume
--last 24h` and its baseline-off projection drivers to tune these thresholds
for the actual host.

Unified policy is the preferred tuning surface for allow/block/trust decisions
and machine-specific alert handling:

```ini
EnableDetectionPolicy=true
PolicyFile=arcane-policy.example.json
```

`config\arcane-policy.example.json` contains one JSON surface for network
allowlists, domain/hash blocklists, trusted process and persistence context,
response allow/block policy, ordered remote endpoint policy, and structured
local alert tuning. Host-specific tuning should copy it to an ignored local
policy file and point `PolicyFile` there.

Detection policy entries in `detection_policies` match fields such as
`rule_id`, `category`, `process_name`, `parent_process`, `signer`,
`path_prefix`, `command_terms`, `user`, `destination_domain`, `ip_cidr`,
`port`, `hash`, and `text_contains`. Supported actions are `trusted_context`,
`lower_score`, `suppress_external`, `raise_score`, `force_alert`, and
`tag_only`.

`suppress_external` keeps the local alert log, incident grouping, daily report
context, and support-bundle summaries intact; it only prevents external
delivery for matching alerts. `lower_score` and `raise_score` adjust the local
score before logging, so the score change remains auditable in the alert body
and `why` metadata.

Preview policy effects against recent local alerts before relying on a rule:

```powershell
.\bin\ArcaneEDR.exe --policy-preview --last 24h --limit 20
```

Preview against a proposed sample alert before matching telemetry exists:

```powershell
.\bin\ArcaneEDR.exe --policy-preview --sample-rule NET-BEACON-TIMING-LOW-RISK --sample-process codex.exe --sample-score 55
.\bin\ArcaneEDR.exe --policy-preview --sample-rule NET-EGRESS-PORT-MISUSE --sample-process ssh.exe --sample-ip 192.168.1.50 --sample-port 22 --sample-user operator
.\bin\ArcaneEDR.exe --policy-preview --sample-rule PS-SUSPICIOUS-COMMAND --sample-process powershell.exe --sample-parent cmd.exe --sample-command "powershell Invoke-WebRequest http://example.invalid/payload"
```

You can also preview against an alert JSON file:

```powershell
.\bin\ArcaneEDR.exe --policy-preview --sample-alert .\sample-alert.json
```

Sample context options include `--sample-process`, `--sample-parent`,
`--sample-user`, `--sample-destination-domain`, `--sample-ip`,
`--sample-port`, `--sample-path`, `--sample-signer`, `--sample-hash`, and
`--sample-command`.

Network port allowlists are in `allowlists.allowed_listening_ports`,
`allowlists.allowed_outbound_ports`, and
`allowlists.process_allowed_outbound_ports` inside `PolicyFile`.
Remote country allowlisting is in `allowlists.allowed_remote_countries`.

Remote endpoint enrichment adds DNS-derived names and remote owner/ASN/country
context to network alerts. Country is best-effort registry/geolocation data,
not proof of physical origin. RDAP is enabled by default because the ordered
endpoint policy uses owner, ASN, and country context to adjust review priority;
this discloses investigated remote IPs to the configured RDAP lookup service.
Optional `ip-api.com` and `ipwhois.io`/`ipwho.is` hooks can fill geolocation
country, owner, or ASN context when local country blocks and RDAP are
incomplete. They are disabled in tracked config. Their free endpoints are for
non-commercial use only; commercial use requires the provider's paid/commercial
plan.

```ini
EnableRemoteEndpointEnrichment=true
EnableRemoteEndpointCountryBlockEnrichment=false
RemoteEndpointCountryBlocksDirectory=country-ip-blocks
EnableRemoteEndpointIpApiGeolocation=false
RemoteEndpointIpApiUrlTemplate=http://ip-api.com/json/{ip}?fields=status,message,countryCode,org,isp,as,asname,query
EnableRemoteEndpointIpWhoisGeolocation=false
RemoteEndpointIpWhoisUrlTemplate=https://ipwho.is/{ip}?fields=success,message,country_code,org,isp,asn,ip
RemoteEndpointGeoProviderMaxLookupsPerPoll=3
EnableRemoteEndpointReverseDns=false
EnableRemoteEndpointRdapEnrichment=true
RemoteEndpointRdapUrlTemplate=https://rdap.org/ip/{ip}
RemoteEndpointEnrichmentTimeoutSeconds=3
RemoteEndpointEnrichmentCacheMinutes=1440
RemoteEndpointRdapMaxLookupsPerPoll=3
EnableRemoteEndpointPolicy=true
```

Remote allow, trust, block, and critical country/owner/domain/CIDR decisions
belong in `remote_endpoint_policies` inside `PolicyFile`. First enabled match
wins. Keep two remote heuristics separate: `allowed_remote_countries` prevents
country-only escalation, while `action: "trust"` with a known
`remote_identity` is the deterministic score-dampening path for trusted
providers. The tracked default trusts Arcane EDR service self-traffic, trusts
known major provider identity such as Microsoft, Cloudflare, Amazon, GitHub,
Anthropic, or Vercel only inside the allowed-country set, treats fully
unresolved country/domain context after enabled local or provider geolocation
enrichment as critical, observes ordinary country-unavailable outcomes as a
score enhancer, and treats countries outside
`allowlists.allowed_remote_countries` as critical when no earlier trust rule
matched. Default allowed countries are `US`, `CA`, `GB`, `IE`, `DE`, `NL`,
`FR`, `SE`, `CH`, `AU`, `NZ`, `JP`, and `SG`.
Country unavailable also becomes critical when paired with first-seen app/IP
context or another stronger suspicious endpoint signal.

`RemoteEndpointCountryBlocksDirectory` can point at an extracted
`ipverse/country-ip-blocks` tree, for example a directory containing
`country\us\ipv4-aggregated.txt` and `country\us\ipv6-aggregated.txt`. Arcane
reads those files locally; it does not download country data at runtime.
`RemoteEndpointGeoProviderMaxLookupsPerPoll` caps combined `ip-api` and
`ipwhois` requests per poll so free/non-commercial endpoints are not hammered.
Arcane tries local country blocks first. If the resolved country is in
`allowlists.allowed_remote_countries`, country alone does not escalate the
alert. If no DNS/domain/company identity is available, Arcane can still use
enabled RDAP, `ip-api`, or `ipwhois` lookups within configured caps so a known
provider `trust` rule can match. Otherwise it tries RDAP for registry owner/ASN
context, then these optional providers only when country or useful owner/ASN
context is still missing.

```json
{
  "id": "example-trust-expected-agent-cloudflare",
  "enabled": false,
  "action": "trust",
  "reason": "Expected agent backend traffic.",
  "match": {
    "process_name": "codex.exe",
    "country": "US",
    "remote_identity": "Cloudflare",
    "port": 443
  }
}
```

Policy text fields use case-insensitive contains matching by default. Prefix an
entry with `regex:` or `re:`, or wrap it as `/pattern/`, for regex matching.
Use JSON arrays for multiple values; strings are treated as one entry.
Supported actions are `critical`, `block`, `trust`, `allow`, and `observe`.
`critical` and `block` create high-score policy alerts. `trust` lowers only
clean timing-only or direct-IP network noise from expected processes. `allow`
skips generic external-remote analysis for the matching endpoint, so keep allow
rules narrow and place more specific block/critical rules above broad allow
rules.
See [docs/remote-endpoint-policy.md](docs/remote-endpoint-policy.md) for the
full match field list and examples.

Maintenance context tuning labels expected admin/build/publish activity without
making it disappear:

```ini
EnableMaintenanceContext=true
MaintenanceContextExternalAlertMinimumScore=95
MaintenanceContextTermGroups=icacls|/inheritance:r,powershell|-executionpolicy bypass|publish.ps1,ArcaneEDR.exe|--validate-config
EnableMaintenanceSessionMarkers=true
MaintenanceSessionMarkerFile=ArcaneMaintenanceSessions.jsonl
MaintenanceSessionDefaultMinutes=60
MaintenanceSessionMaximumMinutes=240
```

Each comma-separated group uses `|` for terms that must all appear in the alert
text. Matching alerts get `maintenance_context=true`, retain their local log and
incident records, and only suppress external delivery when the score is below
`MaintenanceContextExternalAlertMinimumScore`.

For expected work that does not fit a durable term group, start a bounded local
maintenance marker:

```powershell
.\bin\ArcaneEDR.exe --maintenance start --duration 1h --reason publish
.\bin\ArcaneEDR.exe --maintenance list
.\bin\ArcaneEDR.exe --maintenance clear --reason done
```

Active markers label alerts with maintenance context for their configured
window. They do not suppress local evidence, change scores, or perform response
actions.

Low-value repeat dampening reduces external notification volume for the same
stable behavior while preserving local evidence:

```ini
EnableLowValueRepeatDampening=true
LowValueRepeatDampeningMaximumScore=60
LowValueRepeatDampeningWindowMinutes=60
LowValueRepeatDampeningMaxExternalAlertsPerWindow=2
LowValueRepeatDampeningCategories=Network,DNS,Baseline,Reputation,Process
```

When enabled, Arcane allows the first few matching low-score external alerts in
the window, then suppresses additional external delivery for the same repeat
key. Local alert logs, incident grouping, response handling, and high-score
alerts are not affected. Leave `LowValueRepeatDampeningCategories` populated;
an explicitly blank category list disables repeat dampening matches.

Authentication special-privilege tuning keeps Windows `4672` events
correlation-first:

```ini
AuthSpecialPrivilegeRepeatDampeningMinutes=60
AuthSpecialPrivilegeRemoteCorrelationMinutes=15
```

Standalone `4672` events are low-severity local context and repeat-dampened per
principal. If special privileges occur near recent remote logon activity for the
same account, Arcane raises stronger `AUTH-REMOTE-SPECIAL-PRIVILEGES` context.
Remote-style logons with an unspecified source such as `0.0.0.0` are recorded
as low-risk session context rather than ordinary remote source evidence.

Persistence trust handling reduces noise from expected Windows/vendor service
and scheduled-task activity without trusting names by themselves. A service or
task change is classified as trusted-location only when configured trusted
name indicators match a trusted path or trusted signer, and suspicious command,
untrusted user-writable path, and RMM/RAT-like traits are absent. For
scheduled-task create/update events, Arcane also inspects task action XML when
Windows provides it.

Trusted persistence name, path, and signer context lives in
`allowlists.trusted_persistence_*` inside `PolicyFile`.

High-signal file-create detection is Sysmon-backed and intentionally narrow:

```ini
EnableHighSignalFileDetection=true
HighRiskFilePathIndicators=\appdata\roaming\microsoft\windows\start menu\programs\startup\,\programdata\microsoft\windows\start menu\programs\startup\,\windows\system32\tasks\,\appdata\local\google\chrome\user data\default\extensions\,\appdata\local\microsoft\edge\user data\default\extensions\
HighRiskFileExtensions=.exe,.dll,.scr,.com,.msi,.msp,.ps1,.psm1,.vbs,.vbe,.js,.jse,.hta,.bat,.cmd,.lnk,.url,.jar
SensitiveFileNameIndicators=apikey,api_key,access_token,refresh_token,client_secret,private_key,id_rsa,id_ed25519,.pem,.pfx,.env,credentials,token.json
```

These rules do not audit every file write. They depend on Sysmon FileCreate
events for high-risk targets, then alert on executable/script drops,
suspicious writers, agent writes outside approved roots, sensitive-looking
filenames, or recent high-risk drops followed by execution.

Arcane can also group alert records into local investigation incidents. This is
local-only JSONL state, intended to make recent related alerts easier to scan:

```ini
EnableIncidentGrouping=true
IncidentStoreFile=ArcaneIncidents.jsonl
IncidentWindowMinutes=30
IncidentMinimumScore=60
```

List recent incident summaries:

```powershell
.\bin\ArcaneEDR.exe --incidents --last 24h
```

Show the alert timeline for one incident:

```powershell
.\bin\ArcaneEDR.exe --timeline INC-...
```

Summarize recent local alert volume for tuning:

```powershell
.\bin\ArcaneEDR.exe --alert-volume --last 24h
```

Summarize the compact agent activity ledger:

```powershell
.\bin\ArcaneEDR.exe --agent-activity --last 24h
```

The summary groups local alert records by severity, category, rule, and process,
and estimates which records would qualify for external delivery before
provider, rate-limit, retry, or repeat-dampening behavior.
It also prints `BaselineOffExternalQualifiedBeforeRateLimits` and
`baseline_off_external` bucket counts, plus baseline-off projection drivers by
rule and process, so operators can estimate whether turning off
`BaselineLearningMode` would create a notification flood before changing live
config. When records would qualify for current or baseline-off external
delivery, the command also prints compact candidate examples with time, score,
rule, process, maintenance context, and title only. It intentionally avoids raw
entities, paths, command lines, IPs, users, and alert bodies. Service health,
daily report, and AI control notifications are counted as current external
candidates when they are present because those records use the direct
notification path rather than the normal detection threshold path.
Run `--poll-once` first when you want a fresh one-poll sample without leaving
the monitor running.
If the published app uses a protected `LogDirectory` such as `C:\Security`, run
`--poll-once` elevated or collect the sample from a source build with a
user-writable log directory.

External delivery is controlled by config:

```ini
ExternalAlertProvider=Brevo
RequireExternalAlerting=true
MinimumEmailScore=60
ExternalAlertProviderMinimumScores=
ExternalAlertProviderMaxPerHour=
ExternalAlertMaxPerDispatch=3
ExternalAlertMaxPerHour=24
BrevoApiKeyEnvironmentVariable=<configured env var>
BrevoSenderEmail=<verified sender>
BrevoRecipientEmail=<recipient>
```

`ExternalAlertProvider` can be a single provider or a comma-separated list.
Supported providers in the current source tree:

- `Disabled`
- `Brevo`
- `Smtp`
- `Webhook`
- `GenericHttpApi`
- `LocalJsonl`
- `WindowsEventLog`

Example fan-out to Brevo, a local external-alert JSONL file, and Windows Event
Log:

```ini
ExternalAlertProvider=Brevo,LocalJsonl,WindowsEventLog
ExternalAlertProviderMinimumScores=Brevo=90,LocalJsonl=60,WindowsEventLog=75
ExternalAlertProviderMaxPerHour=Brevo=6,WindowsEventLog=12
LocalJsonlAlertSinkFile=ArcaneExternalAlerts.jsonl
WindowsEventLogAlertSource=ArcaneEDR
WindowsEventLogAlertLogName=Application
WindowsEventLogAlertEventId=9100
```

`ExternalAlertProviderMinimumScores` adds provider-specific routing floors after
the global, rule, and category external thresholds. This is useful when one sink
should receive broader telemetry, while email or webhook destinations receive
only higher-confidence alerts. A skipped provider does not remove the local
alert log, incident grouping, or daily report context.

`ExternalAlertProviderMaxPerHour` adds optional per-provider hourly caps after
global rate limits. Use it to keep a noisy provider quiet while still allowing
another configured sink to receive eligible alerts. Daily summary reports are
not counted against provider hourly caps. Service lifecycle notifications are
also exempt so crash recovery and restart notices are not hidden by alert
bursts.
`ExternalAlertMaxPerHour` is the shared runtime cap for normal detection
alerts, AI notifications, and retry deliveries. Daily summary reports and
service lifecycle notifications bypass this cap so scheduled reports and
restart/recovery notices do not compete with alert bursts.

SMTP:

```ini
ExternalAlertProvider=Smtp
SmtpHost=smtp.example.com
SmtpPort=587
SmtpEnableSsl=true
SmtpUsername=alerts@example.com
SmtpPasswordEnvironmentVariable=SMTP_PASSWORD
SmtpSenderEmail=alerts@example.com
SmtpRecipientEmail=security@example.com
```

Webhook or generic HTTP/API JSON POST:

```ini
ExternalAlertProvider=Webhook
WebhookAlertUrl=https://example.com/arcane-alert
WebhookSecretEnvironmentVariable=WEBHOOK_TOKEN
WebhookSecretHeaderName=Authorization
WebhookSecretPrefix=Bearer

ExternalAlertProvider=GenericHttpApi
GenericHttpApiAlertUrl=https://example.com/api/security-alerts
GenericHttpApiSecretEnvironmentVariable=API_TOKEN
GenericHttpApiSecretHeaderName=Authorization
GenericHttpApiSecretPrefix=Bearer
```

The Brevo API key is read from Process, User, then Machine environment scope.
`ExternalAlertSuppressionTermGroups` is a stronger external-only suppression
escape hatch, not the preferred way to classify routine maintenance. It
suppresses external delivery only; local logging and incident grouping remain.

## Health Notifications

Arcane EDR maintains local health state in:

```text
<LogDirectory>\ArcaneServiceHealth.state
```

It can send external notifications when:

- the service starts
- the service starts after a previous run did not record a clean stop
- the daily summary interval elapses

Relevant config:

```ini
NotifyOnServiceStart=true
NotifyOnServiceStop=false
NotifyOnCrashRecovery=true
EnableDailySummary=true
DailySummaryIntervalHours=24
DailySummaryLocalTime=08:00
DailySummaryTimeZoneId=<configured Windows time zone ID>
DailySummaryScore=60
EnableDailySummaryAIAnalysis=true
DailyReportDestinations=ExternalAlertSinks,LocalArchive
HealthHeartbeatSeconds=60
```

The daily report uses a report-specific email layout, not the generic alert
template. It starts with a compact metadata header containing the high-level
determination, compromise assessment, confidence, analyzed system-time window,
generated system time, basis, and recommended next step, then uses compact
tables for critical callouts, health, signal summary, false-positive context,
high-signal details, automation activity, tuning notes, and optional AI
daily analysis. Critical and high-signal tables include process/source context
when the source telemetry provides it. The top-level determination,
compromise assessment, recommended next step, and critical callouts are
deterministic local-telemetry sections; optional AI daily analysis is kept
inside the labeled AI review section as a secondary opinion. The AI
daily prompt is tuned for customer-facing 24-hour review and explicitly treats
alert volume, baseline learning, maintenance context, automation context, and
telemetry gaps as false-positive context rather than proof of compromise.
Daily report structure and local archive output are configurable:

```ini
DailyReportDestinations=ExternalAlertSinks,LocalArchive
DailyReportSections=QuickVerdict,CriticalCallouts,AtAGlance,SignalSummary,FalsePositiveContext,HighSignalDetails,AutomationActivity,AIReview,TuningNotes
DailyReportCriticalCalloutRows=5
DailyReportHighSignalRows=7
DailyReportBucketRows=6
DailyReportAgentBucketRows=3
EnableDailyReportArchive=true
DailyReportArchiveDirectory=reports
DailyReportArchiveFormats=Markdown,Json
DailyReportWebhookUrl=
DailyReportWebhookSecretEnvironmentVariable=
DailyReportWebhookSecretHeaderName=Authorization
DailyReportWebhookSecretPrefix=Bearer
DailyReportWebhookTimeoutSeconds=15
```

`DailyReportDestinations` separates daily reporting from normal alert routing.
`ExternalAlertSinks` sends the daily report through the configured external
alert sinks. `LocalArchive` writes the configured archive formats. `Webhook`
posts the redacted JSON report payload to `DailyReportWebhookUrl`. Use
`DailyReportDestinations=LocalArchive` for archive-only reporting while keeping
real-time alerts enabled, or `DailyReportDestinations=LocalArchive,Webhook` for
archive plus report-specific webhook delivery.
Daily reports delivered through `ExternalAlertSinks` bypass shared and
provider-specific hourly alert caps, but still require a configured external
sink.
Supported destination names are `ExternalAlertSinks`, `LocalArchive`, and
`Webhook`.

Archived reports are written under `LogDirectory` when
`DailyReportArchiveDirectory` is relative. The Markdown archive mirrors the
delivered report body; the JSON archive stores redacted report metadata,
metrics, bucket summaries, high-signal summaries, and AI review metadata
without raw alert bodies, entities, command lines, paths, users, IPs, URLs,
emails, or secrets.

Example report webhook destination:

```ini
DailyReportDestinations=LocalArchive,Webhook
DailyReportWebhookUrl=https://example.com/arcane-daily-report
DailyReportWebhookSecretEnvironmentVariable=ARCANE_REPORT_WEBHOOK_TOKEN
DailyReportWebhookSecretHeaderName=Authorization
DailyReportWebhookSecretPrefix=Bearer
```

Use `--preview-daily-report` while tuning `DailyReportSections` and row limits.
The preview command does not send external notifications and does not call
the AI provider; add `--archive` only when you want the preview written to the configured
archive directory.

Future reporting work should keep moving these sections toward a configurable
reporting engine with additional destinations, schedules, and audience-specific
detail levels.

## AI Log Analysis

Arcane EDR can send a compact log sample to one or more AI analysis providers
for secondary analysis. `v0.4` supports concurrent provider fan-out for OpenAI,
OpenAI-compatible Responses-style endpoints, and native Anthropic Claude
Messages API endpoints. Each provider receives the same compact, redacted
payload and returns the same Arcane result contract.

```ini
EnableAIAnalysis=true
AIAnalysisIntervalMinutes=60
AIAnalysisScoreThreshold=95
AIAnalysisBaselineEmailMinimumScore=95
AIAnalysisMinimumIncludedAlertScore=60
AIAnalysisBaselineMinimumIncludedAlertScore=95
AIAnalysisExcludedRuleIds=AI-LOG-ANALYSIS-ALERT,AI-LOG-ANALYSIS-TEST,SERVICE-STARTED,SERVICE-STOPPED,SERVICE-DAILY-SUMMARY,SERVICE-HEALTH-TEST,TEST-ALERT-DELIVERY
AIAnalysisMaxLogLines=80
AIAnalysisMaxAlertLines=80
AIAnalysisMaxChars=12000
AIAnalysisTimeoutSeconds=30
EnableDailySummaryAIAnalysis=true
```

Single-provider configuration:

```ini
AIAnalysisProviders=OpenAI
AIAnalysisModel=<configured model>
AIAnalysisApiKeyEnvironmentVariable=OpenAIAPIKey_ArcaneEDR
AIAnalysisApiUrl=https://api.openai.com/v1/responses
```

Provider defaults fill common auth headers: OpenAI uses `Authorization` with a
`Bearer ` prefix and defaults to `OpenAIAPIKey_ArcaneEDR`, and Claude uses
`x-api-key` plus `anthropic-version`.

Multi-provider configuration:

```ini
AIAnalysisProviders=OpenAI,Claude
AIAnalysisProviderTypes=OpenAI=OpenAI,Claude=Anthropic
AIAnalysisProviderModels=OpenAI=<configured OpenAI model>,Claude=<configured Claude model>
AIAnalysisProviderApiKeyEnvironmentVariables=OpenAI=OpenAIAPIKey_ArcaneEDR,Claude=ANTHROPIC_API_KEY
AIAnalysisProviderApiUrls=OpenAI=https://api.openai.com/v1/responses,Claude=https://api.anthropic.com/v1/messages
AIAnalysisProviderAuthHeaderNames=OpenAI=Authorization,Claude=x-api-key
AIAnalysisProviderAuthHeaderPrefixes=OpenAI=Bearer,Claude=
AIAnalysisProviderVersionHeaderNames=Claude=anthropic-version
AIAnalysisProviderVersionHeaderValues=Claude=2023-06-01
```

When multiple providers are enabled, Arcane runs them concurrently. A failed
provider is recorded in the provider breakdown without blocking a successful
provider. The aggregate AI review uses the strongest alertable provider result,
or the highest-scored completed result when no provider flags the sample, and
keeps each provider's score, flag, and read visible in the daily report.
Use the provider-specific maps for multi-provider setups; `--validate-config`
warns about unused map entries and single-provider fields that are ignored when
more than one `AIAnalysisProviders` entry is configured.
Set `AIAnalysisAuthHeaderName=` only for a trusted no-auth local endpoint.

The payload is intentionally compact and redacted. It includes health counters,
recent event summaries, alert metadata, and sanitized aggregate context. The
aggregate context includes score buckets, category/rule counts, repeated-rule
indicators, maintenance/agent-context counts, trend counters, and top sanitized
reasons for score-60+ activity. Network alert summaries include bounded remote
enrichment context such as process name, remote port, owner/ASN org, country,
country lookup status, registrable/resolved domain labels, and remote policy id
after redaction; raw IPs, URLs, paths, and command lines remain omitted.
Detailed alert summaries still honor `AIAnalysisMinimumIncludedAlertScore` or
`AIAnalysisBaselineMinimumIncludedAlertScore`.

Arcane EDR does not send alert bodies, entities, command lines, script blocks,
decoded payload previews, usernames, file paths, IPs, URLs, emails, or
configured secret values.

Results are written to:

```text
<LogDirectory>\ArcaneAIAnalysis.jsonl
```

Hourly compact analysis records use `analysis_type=compact_log`; daily report
analysis records use `analysis_type=daily_report`.

If the configured AI provider returns `alertable=true` with a score at or above
`AIAnalysisScoreThreshold`, Arcane EDR sends the model's summary and
recommended action through the configured external alert sinks.

## Baseline Learning

The default deployment learns process/destination and process/domain pairs for
the first 24 hours:

```ini
BaselineEnabled=true
BaselineLearningMode=true
BaselineLearningEmailMinimumScore=90
BaselineWarmupHours=24
```

After the baseline looks comfortable, set `BaselineLearningMode=false` to alert
on new process/domain and process/destination pairs. During baseline learning,
lower-confidence alerts are still logged locally but not emailed unless they
meet `BaselineLearningEmailMinimumScore`.

## Agent Profile

Arcane EDR can label existing alerts that involve known unattended agent
processes. This helps separate ordinary workstation activity from activity that
was agent-launched or agent-adjacent.

Example:

```ini
EnableAgentProfile=true
AgentProcessNames=Codex.exe,codex.exe
AgentChildProcessNames=powershell.exe,pwsh.exe,cmd.exe,git.exe,git-remote-https.exe,node.exe,npm.exe,npm.cmd,python.exe,pip.exe,curl.exe
AgentWorkspaceRoots=C:\Development\
AgentPublishRoots=C:\Applications\
AgentPackageManagerProcesses=git.exe,git-remote-https.exe,node.exe,npm.exe,npm.cmd,python.exe,pip.exe,curl.exe
AgentApprovedAdminTaskNames=\ArcaneEDR\PublishRestart,\ArcaneEDR\InstallService,\ArcaneEDR\ValidateAdmin
AgentSecretIndicatorTerms=apikey,api_key,access_token,refresh_token,client_secret,private_key,id_rsa,.pem,.pfx,.env
EnableAgentAdminCommandGuardrails=true
AgentAdminCommandMinimumScore=84
AgentAdminCommandTerms=-verb runas,runas.exe,schtasks,start-scheduledtask,register-scheduledtask,new-scheduledtask,run-admin-task.cmd,run-admin-task.ps1,admin-task-runner.ps1,new-service,sc.exe create,sc create,set-service,netsh advfirewall,new-netfirewallrule,set-netfirewallrule,remove-netfirewallrule,icacls,takeown,set-acl,reg add,\currentversion\run,set-mppreference,add-mppreference,disableantispyware,disablerealtimemonitoring
EnableAgentSecretReferenceGuardrails=true
AgentSecretReferenceMinimumScore=78
AgentSecretReferenceTerms=apikey,api_key,access_token,refresh_token,client_secret,private_key,id_rsa,id_ed25519,.pem,.pfx,.env,credentials,token.json,aws_access_key_id,azure_client_secret,gcloud,\appdata\local\google\chrome\user data,\appdata\local\microsoft\edge\user data,\mozilla\firefox\profiles
EnableAgentSupplyChainGuardrails=true
AgentSupplyChainMinimumScore=74
AgentSupplyChainTerms=npm install,npm ci,npm exec,npx,pnpm install,yarn install,pip install,pip3 install,python -m pip install,curl,curl.exe,invoke-webrequest,wget,downloadstring,downloadfile,git clone,invoke-restmethod,invoke-expression,install.ps1,install.sh,postinstall
EnableAgentActivityLedger=true
AgentActivityLedgerFile=ArcaneAgentActivity.jsonl
AgentActivityLedgerMinimumScore=60
```

When an alert matches the profile, Arcane appends an `AgentContext` line, an
`agent_context=` entity field, and an additional `why` explanation. This does
not raise the score, bypass cooldowns, trigger response actions, or send email
by itself. It is correlation context for the local log, external alert sinks,
and later review.

When `EnableAgentActivityLedger=true`, Arcane also writes compact records for
agent-involved alerts at or above `AgentActivityLedgerMinimumScore`. The ledger
stores rule, score, process family, agent reason labels, command category,
endpoint category, and file category; it does not store raw command lines,
paths, IPs, users, URLs, or alert bodies.

When `EnableAgentAdminCommandGuardrails=true`, Arcane raises
`AGENT-ADMIN-COMMAND` when PowerShell, Windows process-creation audit, or
Sysmon process telemetry shows an agent-initiated elevation, service,
scheduled-task, firewall, ACL, registry, persistence, or security-control
command that is not one of the configured `AgentApprovedAdminTaskNames`. This
is alert-only evidence; it does not change `ResponseMode` or perform
containment.

When `EnableAgentSecretReferenceGuardrails=true`, Arcane raises
`AGENT-SECRET-REFERENCE` for agent-initiated commands or script blocks that
reference configured token, key, certificate, SSH material, cloud credential,
or browser credential-store indicators.

When `EnableAgentSupplyChainGuardrails=true`, Arcane raises
`AGENT-SUPPLY-CHAIN-COMMAND` for agent-initiated package installs, source
clones, downloads, install scripts, or expression-execution indicators. These
rules are review prompts for unattended agent work, not automatic containment
triggers.

## Custom Rules

Custom rules are compact JSON objects with `source`, `score`, `contains_any`,
optional `process_names`, and a recommendation. They are loaded from
`config\custom-rules.json` and hot-reloaded when the file changes.

## Response Mode

The default is alert-only:

```ini
ResponseMode=AlertOnly
ResponseMinimumScore=95
EnableFirewallBlockResponse=false
EnableProcessTerminationResponse=false
EnableResponsePolicy=true
EnableResponseLedger=true
ResponseLedgerFile=ArcaneResponseLedger.jsonl
EnableResponseFollowUpDetections=true
ResponseProcessRespawnWindowMinutes=10
ResponseProcessRespawnMinimumScore=94
ResponseFollowUpExternalAlertMinimumScore=95
```

Dry-run modes are `DryRunBlockRemoteIp`, `DryRunTerminateProcess`, and
`DryRunBlockAndTerminate`. They evaluate candidate response targets, write
compact local records to `ResponseLedgerFile`, and log what would have
happened, but they do not add firewall rules or kill processes. If response
policy would block the same alert in an active mode, the dry-run ledger records
that policy skip reason.

Active modes are `BlockRemoteIp`, `TerminateProcess`, and
`BlockAndTerminate`. These are intentionally opt-in because false positives can
disrupt legitimate tools. Keep `ResponseMinimumScore` high when testing active
response. Firewall blocking requires `EnableFirewallBlockResponse=true`, and
process termination requires `EnableProcessTerminationResponse=true` because it
cannot be rolled back. Read `docs\response-safety-and-rollback.md` before
enabling active response.

When `EnableResponsePolicy=true`, active response also requires an explicit
allow entry in `response_policy.allowed_rule_ids` or
`response_policy.allowed_categories` inside `PolicyFile`. The example policy
leaves both allowlists empty, so active modes skip every action even if an
action gate is enabled. Dry-run modes remain useful for discovering candidate
rules before adding a narrow allow entry.

Firewall block response rules are named `ArcaneEDR_BLOCK_<response-id>`, where
`response-id` is a GUID recorded in `ResponseLedgerFile` with the triggering
alert rule, score, target, and firewall rule name. List or remove Arcane-owned
firewall blocks with:

```powershell
.\bin\ArcaneEDR.exe --response-firewall list
.\bin\ArcaneEDR.exe --response-firewall remove <response-id-or-ArcaneEDR_BLOCK_guid>
.\bin\ArcaneEDR.exe --response-firewall remove-all
```

If process termination is enabled and a same-named process relaunches within
`ResponseProcessRespawnWindowMinutes`, Arcane raises
`RESPONSE-PROCESS-RESPAWN` as escalatory local evidence. By default,
`ResponseFollowUpExternalAlertMinimumScore=95` keeps these follow-up alerts
from sending external notifications unless the score or local policy warrants
it.

## Hardening Notes

- Run the service as a dedicated low-privilege user.
- Grant that user read access to the app config and write access only to `LogDirectory`.
- Keep Brevo, AI provider, SMTP, and webhook secrets out of config and expose them only through environment variables for the service account.
- Keep allowlists narrow. Start in console mode, observe normal traffic, then tune config.
