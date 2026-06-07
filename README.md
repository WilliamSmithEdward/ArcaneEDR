# Arcane EDR

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

## What It Detects

- New listening TCP/UDP ports.
- New external outbound TCP connections.
- External inbound TCP connections.
- Connections to commonly abused remote ports.
- Connection bursts by process.
- Low-jitter repeated outbound connections that resemble beaconing.
- Process path, command line, parent process, user, signer, and SHA256 context.
- Sysmon process, network, and DNS events when Sysmon is installed.
- PowerShell operational log events, including script block, module, and lifecycle records.
- Windows Security/System events for failed logons, RDP/network logons, privileged logons, service installs, scheduled task changes, and process-creation audit events when enabled.
- Registry Run keys, Startup folders, automatic services, and scheduled-task inventory.
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
- Optional: Sysmon for richer process, network, and DNS telemetry.
- Optional: Brevo transactional email for external alert delivery.
- Optional: OpenAI API key for compact secondary log analysis.

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

Keep machine-specific values, recipient addresses, local paths, and environment
variable names in the ignored local files. The example runtime config disables
external alerting and OpenAI analysis by default.

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
connection, DNS query, and SHA256 hash telemetry. If Sysmon is not installed,
Arcane EDR falls back to netstat-based collection and logs a warning once.

## Test Commands

Test alert delivery:

```powershell
.\bin\ArcaneEDR.exe --test-alert
```

Test service-health notification delivery:

```powershell
.\bin\ArcaneEDR.exe --test-health
```

Force compact OpenAI log analysis:

```powershell
.\bin\ArcaneEDR.exe --test-openai-analysis
```

Preview the exact redacted payload that would be sent to OpenAI without making
an API call:

```powershell
.\bin\ArcaneEDR.exe --preview-openai-payload
```

Generate a privacy-first local support bundle:

```powershell
.\bin\ArcaneEDR.exe --support-bundle
```

The bundle is written under `LogDirectory` and includes version, redacted
config, service health state, collector/sink/runtime checks, recent alert
summaries, recent warning/error lines, and recent incident summaries. It does
not copy raw alert bodies, entities, command lines, script blocks, OpenAI
payloads, or secret values.

List safe detection simulations:

```powershell
.\scripts\simulate-detection.cmd -Scenario List
```

Run one representative simulation:

```powershell
.\scripts\simulate-detection.cmd -Scenario EncodedPowerShell
.\scripts\simulate-detection.cmd -Scenario UnexpectedListener -DurationSeconds 120
.\scripts\simulate-detection.cmd -Scenario ScheduledTaskPersistence
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
conditions that caused it to fire. Email, SMTP, Windows Event Log, local text
logs, local JSONL, webhook, and generic HTTP/API sinks all receive the same
explained alert object.

Alerts also carry a rule `category`, derived from the rule ID. Current
categories include `Network`, `DNS`, `PowerShell`, `Persistence`, `Auth`,
`Process`, `RAT`, `AI`, `Health`, `Integrity`, `Baseline`, `Reputation`,
`Custom`, `Test`, and `General`.

Rule policy tuning is controlled by config:

```ini
DisabledRuleIds=
DisabledRuleCategories=
RuleMinimumEmailScores=NET-EGRESS-NEW-UNTRUSTED=80,BASELINE-NEW-PROCESS-DOMAIN=95
CategoryMinimumEmailScores=Baseline=95,Health=60
```

`DisabledRuleIds` and `DisabledRuleCategories` suppress matching alerts before
local alert logging, incident grouping, response handling, and external
delivery. `RuleMinimumEmailScores` and `CategoryMinimumEmailScores` affect
external delivery only; local logging and incident grouping still use the
normal alert path.

Maintenance context tuning labels expected admin/build/publish activity without
making it disappear:

```ini
EnableMaintenanceContext=true
MaintenanceContextExternalAlertMinimumScore=95
MaintenanceContextTermGroups=icacls|/inheritance:r,powershell|-executionpolicy bypass|publish.ps1,ArcaneEDR.exe|--validate-config
```

Each comma-separated group uses `|` for terms that must all appear in the alert
text. Matching alerts get `maintenance_context=true`, retain their local log and
incident records, and only suppress external delivery when the score is below
`MaintenanceContextExternalAlertMinimumScore`.

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

Persistence trust handling reduces noise from expected Windows/vendor service
and scheduled-task activity without trusting names by themselves. A service or
task change is classified as trusted-location only when configured trusted
name/path indicators match and suspicious command, user-writable path, and
RMM/RAT-like traits are absent.

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

External delivery is controlled by config:

```ini
ExternalAlertProvider=Brevo
RequireExternalAlerting=true
MinimumEmailScore=60
ExternalAlertMaxPerDispatch=3
ExternalAlertMaxPerHour=12
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
LocalJsonlAlertSinkFile=ArcaneExternalAlerts.jsonl
WindowsEventLogAlertSource=ArcaneEDR
WindowsEventLogAlertLogName=Application
WindowsEventLogAlertEventId=9100
```

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
HealthHeartbeatSeconds=60
```

The daily summary includes uptime, poll count, alert count, poll failures,
baseline learning mode, and last clean stop time.

## OpenAI Log Analysis

Arcane EDR can send a compact log sample to the OpenAI Responses API for
secondary analysis. It uses the environment variable configured as
`OpenAIApiKeyEnvironmentVariable` from Process, User, then Machine scope.

```ini
EnableOpenAiLogAnalysis=true
OpenAIAnalysisIntervalMinutes=60
OpenAIAnalysisScoreThreshold=95
OpenAIAnalysisBaselineEmailMinimumScore=95
OpenAIAnalysisMinimumIncludedAlertScore=60
OpenAIAnalysisBaselineMinimumIncludedAlertScore=90
OpenAIAnalysisExcludedRuleIds=OPENAI-LOG-ANALYSIS-ALERT,OPENAI-LOG-ANALYSIS-TEST,SERVICE-STARTED,SERVICE-STOPPED,SERVICE-DAILY-SUMMARY,SERVICE-HEALTH-TEST
OpenAIAnalysisModel=gpt-5.5
OpenAIApiKeyEnvironmentVariable=<configured env var>
OpenAIAnalysisMaxLogLines=80
OpenAIAnalysisMaxAlertLines=80
OpenAIAnalysisMaxChars=12000
```

The payload is intentionally compact and redacted. It includes health counters,
recent event summaries, and alert metadata only: timestamp, rule ID, severity,
category, maintenance-context flag, score, and title. It does not send alert
bodies, entities, command lines, script blocks, decoded payload previews,
usernames, file paths, IPs, URLs, emails, or configured secret values.

Results are written to:

```text
<LogDirectory>\ArcaneOpenAIAnalysis.jsonl
```

If OpenAI returns `alertable=true` with a score at or above
`OpenAIAnalysisScoreThreshold`, Arcane EDR sends a Brevo email with the model's
summary and recommended action.

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
```

When an alert matches the profile, Arcane appends an `AgentContext` line, an
`agent_context=` entity field, and an additional `why` explanation. This does
not raise the score, bypass cooldowns, trigger response actions, or send email
by itself. It is correlation context for the local log, external alert sinks,
and later review.

## Custom Rules

Custom rules are compact JSON objects with `source`, `score`, `contains_any`,
optional `process_names`, and a recommendation. They are loaded from
`config\custom-rules.json` and hot-reloaded when the file changes.

## Response Mode

The default is alert-only:

```ini
ResponseMode=AlertOnly
ResponseMinimumScore=95
```

Other supported modes are `BlockRemoteIp`, `TerminateProcess`, and
`BlockAndTerminate`. These are intentionally opt-in because false positives can
disrupt legitimate tools.

## Hardening Notes

- Run the service as a dedicated low-privilege user.
- Grant that user read access to the app config and write access only to `LogDirectory`.
- Keep Brevo and OpenAI keys out of config and expose them only through environment variables for the service account.
- Keep allowlists narrow. Start in console mode, observe normal traffic, then tune config.
