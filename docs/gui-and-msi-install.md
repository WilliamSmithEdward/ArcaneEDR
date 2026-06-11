# GUI And MSI Install

Arcane EDR `v0.8.x` includes a WinUI operator console and a WiX MSI package.
The GUI targets .NET 10 and uses the stable Windows App SDK `2.1` runtime line.
Release GUI builds are self-contained and carry their .NET and Windows App SDK
runtime files in the `gui` folder.

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

If you intentionally keep using script-based source deployment, refresh the
elevated admin bridge once from an elevated PowerShell session before using
`PublishRestart` on a GUI-era checkout:

```powershell
.\scripts\install-admin-tasks.cmd
```

This updates the protected runner under `C:\ProgramData\ArcaneEDR\AdminTasks`
so it excludes the WinUI source tree during service builds and embeds the
Arcane icon into the service/CLI executable.

## Runtime Model

The release GUI is self-contained. It should not prompt the operator to install
the Windows App Runtime or .NET Desktop Runtime before launching. The build
script intentionally uses `dotnet build` output with `SelfContained=true` and
`WindowsAppSDKSelfContained=true`; `dotnet publish` output is not used for the
WinUI payload because it produced startup crashes during validation.

For development machines, Microsoft publishes Windows App SDK runtime installers
on the official Windows App SDK downloads page. Runtime installers are useful
for diagnostics and framework-dependent experiments, but they are not required
for the release GUI payload.

## Install

MSI is the preferred operator install, upgrade, repair, and uninstall path for
local deployments. It keeps the service, GUI, Start menu shortcut, versioned
product files, and future installer checks on one coherent track.

Run the MSI from an elevated installer prompt or by approving UAC:

```powershell
msiexec.exe /i .\artifacts\ArcaneEDR-<version>.msi /l*v .\artifacts\ArcaneEDR-<version>-install.log
```

The MSI installs:

- Windows service executable
- WinUI GUI operator console
- Start menu shortcut
- config examples
- scripts, docs, and assets

The MSI starts the `ArcaneEDR` service during install and stops/removes it
during uninstall.

## Legacy Local Migration

Older local deployments may have a script-installed service under
`C:\Applications\ArcaneEDR` without Windows Installer product state. Do not run
the stale `PublishRestart` task against a GUI-era checkout unless the protected
admin runner has been refreshed; old runners compile every `src\*.cs` file and
will trip over the WinUI project.

For this migration, use the dedicated MSI-local installer from an elevated
PowerShell session:

```powershell
.\scripts\build-msi.cmd
.\scripts\install-msi-local.cmd -MigrateLegacyService
```

The script:

- requires an elevated PowerShell session
- resolves the MSI from `artifacts`
- installs into the folder from `config\Deployment.config`, normally
  `C:\Applications\ArcaneEDR` for local operator deployments
- creates a timestamped operator-state backup under `C:\Security\AdminTasks`
- restores existing non-example config files and local state folders after MSI
  product files are installed
- preserves local JSONL evidence, reports, incidents, and support bundles
- stops and deletes only the legacy Windows service registration when
  `-MigrateLegacyService` is supplied
- lets MSI own the service, GUI, Start menu shortcut, repair, upgrade, and
  uninstall path after migration
- writes a verbose MSI log under `C:\Security\AdminTasks`
- runs `--version` and `--validate-config` after install
- starts the service after validation

## Script-Based Deployment

The publish and admin-task scripts remain supported for development,
diagnostics, and break-glass local recovery. They should not be the normal
operator upgrade path once an MSI deployment is in use.

Use scripts when you are iterating from source, repairing the protected admin
bridge, or intentionally testing the service without running the installer.
Otherwise, prefer the MSI so the installed service, GUI, shortcuts, and
installer product state stay aligned.

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

- Overview: service health, validation blockers, signal picture, and targeted
  review priorities
- Alerts: filterable/sortable table, alert volume, and raw local JSONL evidence
- Policy: policy inspect and sample preview
- Reports: daily report preview and send
- Configuration: guided settings, advanced key/value editing, policy JSON,
  validation, paths, and guarded reset
- Maintenance: maintenance markers, admin bridge tasks, test notifications,
  poll-once, AI payload/test utilities, incidents, agent activity, support
  bundle, and response firewall review

Active response remains controlled by service config. Keep
`ResponseMode=AlertOnly` unless active response testing is intentional.
