# Step-By-Step Install Guide

This guide installs Arcane EDR from the release MSI and gets the Windows
service running. It assumes no project knowledge.

Use this guide when you want the normal installed app. Developers who want to
edit source code should use the source-clone workflow in the README.

## What You Will End With

- Arcane EDR installed in `C:\Program Files\Arcane EDR`.
- Logs and mutable service state written to `%ProgramData%\Arcane EDR`.
- A Windows service named `ArcaneEDR`.
- Local alert logs, even if email or external alerting is not configured.
- Optional Sysmon telemetry if you install Sysmon.

## Before You Start

You need:

- A Windows machine where you are allowed to install services.
- PowerShell.
- Administrator rights.
- The Arcane EDR release MSI from the GitHub releases page.

Optional:

- Sysmon from Microsoft Sysinternals.
- A Brevo API key if you want email alerts through Brevo.
- An AI provider API key if you want compact AI-assisted log analysis.

Secrets should go in environment variables, not in config files.

## 1. Open PowerShell As Administrator

Open the Start menu, search for `PowerShell`, right-click it, and choose
`Run as administrator`.

Most commands in this guide assume that Administrator PowerShell window.

## 2. Create The Log Folder

The MSI creates the standard mutable data directory under
`%ProgramData%\Arcane EDR`.

## 3. Install Arcane EDR

Put the downloaded release MSI in your Downloads folder. Then run:

```powershell
$msi = Get-ChildItem "$env:USERPROFILE\Downloads\ArcaneEDR-*.msi" |
    Sort-Object LastWriteTime -Descending |
    Select-Object -First 1

if (!$msi) {
    throw "No ArcaneEDR release MSI found in Downloads."
}

msiexec.exe /i $msi.FullName /l*v "$env:TEMP\ArcaneEDR-install.log"
cd "C:\Program Files\Arcane EDR"
```

You should now see folders such as `bin`, `config`, `scripts`, and `docs`.

Check:

```powershell
Get-ChildItem
```

## 4. Create Local Config Files

Arcane EDR ships with example config files. Copy them to live local config
files:

```powershell
Copy-Item .\config\ArcaneEDR.example.config .\config\ArcaneEDR.config
Copy-Item .\config\Deployment.example.config .\config\Deployment.config
```

These local files are where machine-specific settings belong.

## 5. Review The Main Config

Open the runtime config:

```powershell
notepad .\config\ArcaneEDR.config
```

For a first install, keep the defaults unless you already know you want email
or AI analysis.

Confirm these values are set the way you want:

```ini
ServiceName=ArcaneEDR
ServiceDisplayName=Arcane EDR
LogDirectory=C:\ProgramData\Arcane EDR
ResponseMode=AlertOnly
EnableFirewallBlockResponse=false
EnableProcessTerminationResponse=false
EnableResponsePolicy=true
```

For a first install, `AlertOnly` is the safest response mode. Before enabling
dry-run or active response, read `docs\response-safety-and-rollback.md`.
Active response requires both the action gate and an explicit response-policy
allow entry.

Save and close Notepad.

## 6. Optional: Configure Email Alerts

You can skip this section and still install Arcane EDR. Alerts will still be
written locally.

To use Brevo email alerts, put the API key in a machine environment variable:

```powershell
[Environment]::SetEnvironmentVariable("BrevoAPIKey", "paste-your-key-here", "Machine")
```

Then open the config:

```powershell
notepad .\config\ArcaneEDR.config
```

Set the email-related values:

```ini
ExternalAlertProvider=Brevo
RequireExternalAlerting=true
BrevoApiKeyEnvironmentVariable=BrevoAPIKey
BrevoSenderEmail=your-verified-sender@example.com
BrevoSenderName=Arcane EDR
BrevoRecipientEmail=your-recipient@example.com
MinimumEmailScore=60
```

Use a Brevo sender address that is verified in Brevo.

Save and close Notepad.

## 7. Optional: Configure AI Analysis

You can skip this section. Arcane EDR does not require AI analysis. The example
below configures OpenAI; additional providers such as Claude can be added with
`AIAnalysisProviders` and the provider-specific maps.

Put the API key in a machine environment variable:

```powershell
[Environment]::SetEnvironmentVariable("OpenAIAPIKey_ArcaneEDR", "paste-your-key-here", "Machine")
```

Then open the config:

```powershell
notepad .\config\ArcaneEDR.config
```

Set:

```ini
EnableAIAnalysis=true
AIAnalysisProviders=OpenAI
AIAnalysisModel=<configured OpenAI model>
AIAnalysisApiKeyEnvironmentVariable=OpenAIAPIKey_ArcaneEDR
AIAnalysisIntervalMinutes=60
```

Arcane EDR sends a compact redacted payload. It should not send raw command
lines, script blocks, user paths, IPs, URLs, emails, or secrets by default.

Save and close Notepad.

## 8. Validate The Install

Run:

```powershell
.\bin\ArcaneEDR.exe --validate-config
```

To validate a specific staged config file, pass its path:

```powershell
.\bin\ArcaneEDR.exe --validate-config .\config\ArcaneEDR.config
```

Good output ends with:

```text
Validation summary: 0 error(s), 0 warning(s).
```

Warnings do not always block install, but review them before continuing.
Errors should be fixed before relying on the service.

## 9. Optional: Install Sysmon

Arcane EDR works without Sysmon, but Sysmon gives better process, network, DNS,
and hash telemetry.

Download Sysmon from Microsoft Sysinternals. Put `Sysmon64.exe` here:

```text
C:\Program Files\Arcane EDR\tools\Sysmon64.exe
```

If the `tools` folder does not exist, create it:

```powershell
New-Item -ItemType Directory -Force -Path .\tools
```

Then run:

```powershell
.\scripts\install-sysmon.cmd
```

Check:

```powershell
Get-Service Sysmon64
Get-WinEvent -ListLog "Microsoft-Windows-Sysmon/Operational"
```

Sysmon should show as `Running`.

## 10. Confirm The Windows Service

The MSI installs and starts the `ArcaneEDR` Windows service. Check it:

```powershell
Get-Service ArcaneEDR
```

The status should be `Running`. Confirm the service is using the MSI-owned
Program Files path:

```powershell
sc.exe qc ArcaneEDR
```

The binary path should be:

```text
C:\Program Files\Arcane EDR\bin\ArcaneEDR.exe
```

If you changed config after MSI install, restart the service:

```powershell
Restart-Service ArcaneEDR
```

## 11. Confirm Logs Are Being Written

Run:

```powershell
Get-ChildItem "$env:ProgramData\Arcane EDR"
Get-Content "$env:ProgramData\Arcane EDR\ArcaneEDR.log" -Tail 40
```

You should see Arcane EDR log entries.

The most important local files are:

```text
C:\ProgramData\Arcane EDR\ArcaneEDR.log
C:\ProgramData\Arcane EDR\ArcaneAlerts.jsonl
C:\ProgramData\Arcane EDR\ArcaneServiceHealth.state
```

## 12. Send Test Notifications

Test alert delivery:

```powershell
.\bin\ArcaneEDR.exe --test-alert
```

Test service-health notification delivery:

```powershell
.\bin\ArcaneEDR.exe --test-health
```

If email is configured, you should receive test emails.

If email is not configured, the tests may only write local logs depending on
your config.

## 13. Know The Basic Service Commands

Stop Arcane EDR:

```powershell
Stop-Service ArcaneEDR
```

Start Arcane EDR:

```powershell
Start-Service ArcaneEDR
```

Restart Arcane EDR:

```powershell
Restart-Service ArcaneEDR
```

Check status:

```powershell
Get-Service ArcaneEDR
```

## 14. Uninstall

Use Windows Settings > Apps, or run from Administrator PowerShell:

```powershell
msiexec.exe /x {PRODUCT-CODE-FROM-APPS-AND-FEATURES}
```

The MSI stops/removes the Windows service and removes product files. Local logs
under `%ProgramData%\Arcane EDR` are not deleted.

## Troubleshooting

### PowerShell says scripts are disabled

Use the `.cmd` wrappers for optional script-based maintenance tasks:

```powershell
.\scripts\install-sysmon.cmd
```

The wrappers handle the execution policy for that command.

### The service already exists

For a clean cutover to the MSI-owned Program Files install, run the helper from
an elevated PowerShell session:

```powershell
.\scripts\install-msi-local.cmd -ReplaceExistingService
```

This removes an existing service registration only when explicitly requested,
then verifies the new service path.

### Repair Or Reinstall MSI

Run the MSI again from Administrator PowerShell:

```powershell
msiexec.exe /fa .\ArcaneEDR-<version>.msi /l*v "$env:TEMP\ArcaneEDR-repair.log"
```

### No email arrived

Check:

```powershell
.\bin\ArcaneEDR.exe --validate-config
Get-Content "$env:ProgramData\Arcane EDR\ArcaneEDR.log" -Tail 80
```

Common causes:

- `ExternalAlertProvider` is not set to `Brevo`.
- `RequireExternalAlerting` is false.
- The sender email is not verified in Brevo.
- The API key environment variable was created after the service started.
- The service needs a restart after changing machine environment variables.

Restart:

```powershell
Restart-Service ArcaneEDR
```

### Sysmon install fails

Check that this file exists:

```powershell
Test-Path "C:\Program Files\Arcane EDR\tools\Sysmon64.exe"
```

If it returns `False`, download Sysmon from Microsoft Sysinternals and put
`Sysmon64.exe` in the `tools` folder.

### Alerts are noisy after first install

Leave baseline learning enabled for at least 24 hours on a noisy workstation.
During that time, Arcane EDR learns normal process and destination pairs and
keeps lower-confidence noise mostly local.

Check the baseline settings:

```ini
BaselineEnabled=true
BaselineLearningMode=true
BaselineWarmupHours=24
```

After the machine looks stable, you can tune rules and then turn learning mode
off.

## Success Checklist

You are done when all of these are true:

- `Get-Service ArcaneEDR` shows `Running`.
- `%ProgramData%\Arcane EDR\ArcaneEDR.log` exists and is updating.
- `%ProgramData%\Arcane EDR\ArcaneAlerts.jsonl` exists.
- `.\bin\ArcaneEDR.exe --validate-config` has no errors.
- `.\bin\ArcaneEDR.exe --test-alert` works locally or sends email.
- If Sysmon is installed, `Get-Service Sysmon64` shows `Running`.
