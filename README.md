# Arcane EDR

Small Windows service that watches active TCP/UDP activity, enriches it with
host context, scores suspicious behavior, writes local logs, and sends qualified
alerts through Brevo.

The implementation intentionally uses only .NET Framework and built-in Windows
tools so it can be built without downloading packages.

## Coverage

- New listening TCP/UDP ports.
- New external outbound TCP connections.
- External inbound TCP connections.
- Connections to commonly abused remote ports.
- Connection bursts by process.
- Repeated low-jitter outbound connection patterns that resemble beaconing.
- Process path, command line, parent, user, signer, and SHA256 context.
- Sysmon process, network, and DNS events when Sysmon is installed.
- PowerShell operational log events, including script block/module/lifecycle records.
- Windows Security/System events for failed logons, RDP/network logons, privileged logons, service installs, scheduled task changes, and process-creation audit events when enabled.
- Registry Run keys, Startup folders, automatic services, and scheduled-task inventory.
- LOLBin and script-runtime external network activity.
- Encoded or base64-obfuscated PowerShell/CLI commands.
- Suspicious parent/child process chains.
- Unsigned executables launched from user-writable paths.
- First-seen executable/persistence reputation cache.
- Local JSON custom rules in `config\custom-rules.json`.
- Known RMM/RAT process names.
- Blocked domains, hashes, IPs, and CIDRs.
- High-entropy DNS and dynamic DNS providers.
- Optional DNS-over-HTTPS resolver detection.
- Optional DNS resolver enforcement.
- Untrusted process connections to internal lateral-movement ports.

## Separation Of Concerns

- `src/Collection`: captures netstat, Sysmon, PowerShell, Windows Event Log, and persistence telemetry.
- `src/Enrichment`: adds process path, command line, parent, hash, signer, and user context.
- `src/Detection`: applies traffic, host, process, DNS, reputation, custom, baseline, and RAT-oriented rules.
- `src/Alerting`: handles alert cooldowns and provider-specific delivery sinks.
- `src/Response`: optional firewall block and process termination actions.
- `src/Logging`: writes text logs and JSONL alert records with rotation.
- `src/Configuration`: loads allowlists, thresholds, alert settings, and rule options.
- `src/Models`: shared alert, process, DNS, and network endpoint models.
- `src/Utils`: CIDR, IP, domain, filesystem, and port-range helpers.
- `src/Runtime`: service polling, health, and integrity checks.
- `src/Validation`: offline configuration and environment checks.

This is not a packet sniffer or full EDR platform. It is a lightweight host
network and telemetry sensor intended to catch unexpected activity from an
agent/sandbox workstation.

## Build

```powershell
.\scripts\build.ps1
```

## Configuration Ownership

Machine/user-specific values are kept in config files:

- `config\ArcaneEDR.example.config`: tracked template with safe defaults for
  GitHub. External alerting and OpenAI analysis are disabled in this template.
- `config\ArcaneEDR.config`: untracked local/runtime config for log directory,
  alert recipients/senders, environment variable names, event log names,
  thresholds, schedules, and detection tuning.
- `config\Deployment.example.config`: tracked template for publish/install
  defaults.
- `config\Deployment.config`: untracked local deployment config for publish
  destination, application folder name, executable name, Sysmon executable name,
  and Sysmon config filename.

Source and scripts use generic fallbacks only. Keep machine-specific values out
of the repository. For local development, copy the example config and edit the
copy:

```powershell
Copy-Item .\config\ArcaneEDR.example.config .\config\ArcaneEDR.config
Copy-Item .\config\Deployment.example.config .\config\Deployment.config
```

The published setup uses `config\ArcaneEDR.config` in the published application
folder as the runtime source of truth.

## Publish

Publish the runnable app to the `DestinationRoot` and `ApplicationName` defined
in local `config\Deployment.config`, or `config\Deployment.example.config` when
no local deployment config exists:

```powershell
.\scripts\publish.ps1
```

The published folder contains the executable, runtime config, deployment config,
docs, Sysmon config, and service install scripts.

If the published folder already has `config\ArcaneEDR.config`, publish preserves
that live machine config and writes the source config as
`config\ArcaneEDR.example.config`. Use `-OverwriteConfig` only when you
intentionally want to replace the live runtime config.

Likewise, an existing published `config\Deployment.config` is preserved by
default. Use `-OverwriteDeploymentConfig` only when you intentionally want to
replace the live deployment config.

## Optional Sysmon

Sysmon is not bundled. Place the executable named by
`SysmonExecutableName` in local `config\Deployment.config` inside the published
`tools` folder, then install it with:

```powershell
.\scripts\install-sysmon.ps1
```

The included `config\arcaneedr-sysmon.xml` enables process creation, network
connection, DNS query, and SHA256 hash telemetry. If Sysmon is not installed,
the service falls back to netstat-based collection and logs a warning once.

## Test

Console mode:

```powershell
.\bin\<ExecutableName> --console
```

Test alert delivery:

```powershell
.\bin\<ExecutableName> --test-alert
```

Test service-health notification delivery:

```powershell
.\bin\<ExecutableName> --test-health
```

Force compact OpenAI log analysis:

```powershell
.\bin\<ExecutableName> --test-openai-analysis
```

Preview the exact redacted payload that would be sent to OpenAI, without making
an API call:

```powershell
.\bin\<ExecutableName> --preview-openai-payload
```

Validate config and environment:

```powershell
.\bin\<ExecutableName> --validate-config
```

The forced test sends the OpenAI result by email even if the model decides the
sample is not alert-worthy. The hourly production path emails only when the
model returns `alertable=true` and the score meets `OpenAIAnalysisScoreThreshold`.

`--validate-config` checks config parsing, log-directory writability, Brevo and
OpenAI key visibility, Sysmon service/log access, PowerShell/Security/System log
readability, response-mode safety, and custom-rule JSON syntax. Some event logs
may warn in a non-admin console while still working under the installed service
account.

## Install As A Windows Service

Run PowerShell as Administrator:

```powershell
.\scripts\install-service.ps1
```

The service is installed using `ServiceName`, `ServiceDisplayName`, and
`ServiceDescription` from `config\ArcaneEDR.config`.

## Brevo Alerting

External alert delivery is configured for Brevo:

```ini
ExternalAlertProvider=Brevo
MinimumEmailScore=60
ExternalAlertMaxPerDispatch=3
ExternalAlertMaxPerHour=12
ExternalAlertSuppressionTermGroups=icacls|/inheritance:r,icacls|/grant:r
BrevoApiKeyEnvironmentVariable=<configured env var>
BrevoSenderEmail=<verified sender>
BrevoRecipientEmail=<recipient>
```

The configured Brevo API-key environment variable is read from Process, User,
then Machine environment scope. Alerts at or above `MinimumEmailScore` are sent
externally. All alerts are always written locally under `LogDirectory`:

`ExternalAlertSuppressionTermGroups` suppresses email only, not local logging.
Each comma-separated group uses `|` for terms that must all appear. This is for
planned maintenance commands such as ACL hardening.

```text
<LogDirectory>\ArcaneEDR.log
<LogDirectory>\ArcaneAlerts.jsonl
```

## Self-Healing And Health Notifications

The installer configures Windows Service Control Manager recovery actions:

- restart after 60 seconds on first failure
- restart after 60 seconds on second failure
- restart after 5 minutes on subsequent failure
- reset the failure counter after 24 hours

The service also maintains local health state in:

```text
<LogDirectory>\ArcaneServiceHealth.state
```

By default it sends Brevo email when:

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

## Hourly OpenAI Log Analysis

The service can send a compact hourly log sample to the OpenAI Responses API for
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
recent monitor-event summaries, and alert metadata only: timestamp, rule ID,
severity, score, and title. It does not send alert bodies, entities, command
lines, script blocks, decoded payload previews, usernames, file paths, IPs,
URLs, emails, or configured secret values. Results are written to:

```text
<LogDirectory>\ArcaneOpenAIAnalysis.jsonl
```

If OpenAI returns `alertable=true` with a score at or above
`OpenAIAnalysisScoreThreshold`, the service sends a Brevo email with the model's
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

After you are comfortable with the baseline, set `BaselineLearningMode=false` to
alert on new process/domain and process/destination pairs.

During baseline learning, lower-confidence alerts are still logged locally but
not emailed unless they meet `BaselineLearningEmailMinimumScore`.

## Host Intelligence

Additional host-side detection is controlled independently:

```ini
EnablePowerShellLogIngestion=true
EnableWindowsEventIngestion=true
EnablePersistenceInventory=true
EnableReputationCache=true
EnableCustomRules=true
CustomRulesFile=custom-rules.json
```

PowerShell events are scored for encoded commands, download cradles, hidden/no
profile/bypass execution, Defender tampering, and persistence commands. Windows
events are scored for repeated failed remote logons, RDP/network logons, service
installs, scheduled-task changes, and suspicious process-creation audit records.
Persistence inventory alerts at low severity for first-seen entries and higher
severity when paths, commands, or tool names resemble RAT/RMM persistence.

Custom rules are compact JSON objects with `source`, `score`, `contains_any`,
optional `process_names`, and a recommendation. They are loaded from the config
folder and hot-reloaded when the file changes.

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
- Keep the Brevo API key out of config and expose it only through the configured environment variable for the service account.
- Keep allowlists narrow. Start in console mode, observe normal traffic, then tune config.
