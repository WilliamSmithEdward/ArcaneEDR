# Step-By-Step Install Guide

This guide installs Arcane EDR from a release ZIP and gets the Windows service
running. It assumes no project knowledge.

Use this guide when you want the normal installed app. Developers who want to
edit source code should use the source-clone workflow in the README.

## What You Will End With

- Arcane EDR installed in `C:\Applications\ArcaneEDR`.
- Logs written to `C:\Security`.
- A Windows service named `ArcaneEDR`.
- Local alert logs, even if email or external alerting is not configured.
- Optional Sysmon telemetry if you install Sysmon.

## Before You Start

You need:

- A Windows machine where you are allowed to install services.
- PowerShell.
- Administrator rights.
- The Arcane EDR release ZIP from the GitHub releases page.

Optional:

- Sysmon from Microsoft Sysinternals.
- A Brevo API key if you want email alerts through Brevo.
- An AI provider API key if you want compact AI-assisted log analysis; OpenAI
  is the default provider.

Secrets should go in environment variables, not in config files.

## 1. Open PowerShell As Administrator

Open the Start menu, search for `PowerShell`, right-click it, and choose
`Run as administrator`.

Most commands in this guide assume that Administrator PowerShell window.

## 2. Create The Install And Log Folders

```powershell
New-Item -ItemType Directory -Force -Path C:\Applications
New-Item -ItemType Directory -Force -Path C:\Security
```

## 3. Unzip Arcane EDR

Put the downloaded release ZIP in your Downloads folder. Then run:

```powershell
$zip = Get-ChildItem "$env:USERPROFILE\Downloads\ArcaneEDR-*.zip" |
    Sort-Object LastWriteTime -Descending |
    Select-Object -First 1

if (!$zip) {
    throw "No ArcaneEDR release ZIP found in Downloads."
}

New-Item -ItemType Directory -Force -Path C:\Applications\ArcaneEDR
Expand-Archive -LiteralPath $zip.FullName -DestinationPath C:\Applications\ArcaneEDR -Force
cd C:\Applications\ArcaneEDR
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
LogDirectory=C:\Security
ResponseMode=AlertOnly
```

For a first install, `AlertOnly` is the safest response mode.

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

You can skip this section. Arcane EDR does not require AI analysis. The default
provider is OpenAI, and v0.4 also supports OpenAI-compatible Responses-style
endpoints through `AIAnalysisProvider=OpenAICompatible`.

Put the API key in a machine environment variable:

```powershell
[Environment]::SetEnvironmentVariable("OpenAIAPIKeyArcaneEDR", "paste-your-key-here", "Machine")
```

Then open the config:

```powershell
notepad .\config\ArcaneEDR.config
```

Set:

```ini
EnableOpenAiLogAnalysis=true
AIAnalysisProvider=OpenAI
OpenAIApiKeyEnvironmentVariable=OpenAIAPIKeyArcaneEDR
OpenAIAnalysisIntervalMinutes=60
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
Errors should be fixed before installing the service.

## 9. Optional: Install Sysmon

Arcane EDR works without Sysmon, but Sysmon gives better process, network, DNS,
and hash telemetry.

Download Sysmon from Microsoft Sysinternals. Put `Sysmon64.exe` here:

```text
C:\Applications\ArcaneEDR\tools\Sysmon64.exe
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

## 10. Install The Windows Service

Run:

```powershell
.\scripts\install-service.cmd
```

Expected result:

```text
Installed and started ArcaneEDR
```

Check the service:

```powershell
Get-Service ArcaneEDR
```

The status should be `Running`.

## 11. Confirm Logs Are Being Written

Run:

```powershell
Get-ChildItem C:\Security
Get-Content C:\Security\ArcaneEDR.log -Tail 40
```

You should see Arcane EDR log entries.

The most important local files are:

```text
C:\Security\ArcaneEDR.log
C:\Security\ArcaneAlerts.jsonl
C:\Security\ArcaneServiceHealth.state
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

From Administrator PowerShell in `C:\Applications\ArcaneEDR`:

```powershell
.\scripts\uninstall-service.cmd
```

This removes the Windows service. It does not delete your logs.

## Troubleshooting

### PowerShell says scripts are disabled

Use the `.cmd` wrappers:

```powershell
.\scripts\install-service.cmd
.\scripts\install-sysmon.cmd
```

The wrappers handle the execution policy for that command.

### The service already exists

Uninstall first:

```powershell
.\scripts\uninstall-service.cmd
```

Then install again:

```powershell
.\scripts\install-service.cmd
```

### No email arrived

Check:

```powershell
.\bin\ArcaneEDR.exe --validate-config
Get-Content C:\Security\ArcaneEDR.log -Tail 80
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
Test-Path C:\Applications\ArcaneEDR\tools\Sysmon64.exe
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
- `C:\Security\ArcaneEDR.log` exists and is updating.
- `C:\Security\ArcaneAlerts.jsonl` exists.
- `.\bin\ArcaneEDR.exe --validate-config` has no errors.
- `.\bin\ArcaneEDR.exe --test-alert` works locally or sends email.
- If Sysmon is installed, `Get-Service Sysmon64` shows `Running`.
