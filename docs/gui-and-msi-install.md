# GUI And MSI Install

Arcane EDR `v0.8.x` includes a WinUI operator console and a WiX MSI package.

## Build

Build the service, GUI, release ZIP, and MSI from the source checkout:

```powershell
.\scripts\test-fixtures.cmd
.\scripts\build-gui.cmd
.\scripts\package-release.cmd
.\scripts\build-msi.cmd
```

Artifacts are written to `artifacts`:

- `ArcaneEDR-<version>.zip`
- `ArcaneEDR-<version>.zip.sha256.txt`
- `ArcaneEDR-<version>.msi`
- `ArcaneEDR-<version>.msi.sha256.txt`

## Admin Task Refresh

If you are upgrading an existing local deployment from a pre-GUI build, refresh
the elevated admin bridge once from an elevated PowerShell session before using
`PublishRestart`:

```powershell
.\scripts\install-admin-tasks.cmd
```

This updates the protected runner under `C:\ProgramData\ArcaneEDR\AdminTasks`
so it excludes the WinUI source tree during service builds and embeds the
Arcane icon into the service/CLI executable.

## Install

Run the MSI from an elevated installer prompt or by approving UAC:

```powershell
msiexec.exe /i .\artifacts\ArcaneEDR-0.8.1.msi /l*v .\artifacts\ArcaneEDR-0.8.1-install.log
```

The MSI installs:

- Windows service executable
- WinUI GUI operator console
- Start menu shortcut
- config examples
- scripts, docs, and assets

The MSI starts the `ArcaneEDR` service during install and stops/removes it
during uninstall.

## Config Preservation

Local config and evidence are operator-owned state. The MSI installs examples
and product files; normal install, upgrade, repair, reinstall, and uninstall
flows should preserve local config, logs, reports, incidents, response ledgers,
and support bundles.

If defaults need to replace local config, open the GUI Configuration page and
use the guarded reset flow. It requires a warning checkbox and writes a backup
before replacing local runtime and deployment config files with defaults.

## GUI

The GUI runs as a standard-user app and uses Arcane's CLI/state files for
operator workflows:

- Overview: service and health state
- Alerts: alert volume and recent local JSONL
- Policy: policy inspect and sample preview
- Reports: daily report preview and send
- Configuration: validation, paths, and guarded reset
- Maintenance: markers, admin bridge, support bundle, and response firewall
  review

Active response remains controlled by service config. Keep
`ResponseMode=AlertOnly` unless active response testing is intentional.
