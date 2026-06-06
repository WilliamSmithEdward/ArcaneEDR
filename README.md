# Arcane EDR

Arcane EDR is a lightweight Windows service for host network and telemetry
detection. It watches TCP/UDP activity, enriches events with local process and
host context, scores suspicious behavior, writes local evidence, and can send
qualified alerts through Brevo.

The project intentionally uses .NET Framework and built-in Windows components
only, so it can be built on a Windows host without downloading NuGet packages.

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
Windows sensor intended for agent workstations, sandbox hosts, and small
environments where local visibility and simple alerting are useful.

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

## Alerting

All alerts are always written locally under `LogDirectory`:

```text
<LogDirectory>\ArcaneEDR.log
<LogDirectory>\ArcaneAlerts.jsonl
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

The Brevo API key is read from Process, User, then Machine environment scope.
`ExternalAlertSuppressionTermGroups` suppresses email only, not local logging.
Each comma-separated group uses `|` for terms that must all appear.

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
score, and title. It does not send alert bodies, entities, command lines,
script blocks, decoded payload previews, usernames, file paths, IPs, URLs,
emails, or configured secret values.

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
