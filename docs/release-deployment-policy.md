# Release And Deployment Policy

Arcane EDR separates source work from live deployment.

The default rule is simple:

- Edit, build, and validate from the source folder.
- Do not redeploy the live application for ordinary source or documentation
  changes.
- Deploy to the live application folder only when cutting a tagged release or
  when the operator explicitly asks for a live update.

This keeps the running monitor stable while development continues.

## Paths

Source folder:

```text
<repo-root>
```

Default live application folder:

```text
C:\Program Files\Arcane EDR
```

Default machine data/log folder:

```text
%ProgramData%\Arcane EDR
```

## Normal Development

During normal development:

```powershell
cd <repo-root>
.\scripts\build.cmd
.\bin\ArcaneEDR.exe --validate-config
```

This validates source changes without touching the live service.

If the live service is temporarily running from the source `bin` folder and
locks `ArcaneEDR.exe`, build a disposable check executable instead:

```powershell
.\scripts\build.cmd -OutputPath bin\ArcaneEDR.check.exe
.\bin\ArcaneEDR.check.exe --validate-config
```

For the `v0.8.0` GUI/MSI track, also validate:

```powershell
.\scripts\build-gui.cmd
.\scripts\build-msi.cmd
.\scripts\test-fixtures.cmd
```

Documentation-only changes do not require build, publish, service restart, or
redeploy.

## Tagged Release Deployment

When a new release tag is intentionally cut, the release process creates ZIP
and MSI artifacts. For operator machines, use the MSI so Windows Installer owns
the service, GUI, shortcut, repair, upgrade, and uninstall path.

Preferred deployment path from an elevated PowerShell session:

```powershell
cd <repo-root>
.\scripts\install-msi-local.cmd -ReplaceExistingService
```

This installs product files under `C:\Program Files\Arcane EDR`, uses
`%ProgramData%\Arcane EDR` for first-install mutable logs/state, replaces an
existing service registration when explicitly requested, and verifies the
installed executable version, service path, config, and service status.

The constrained admin task bridge remains available for source-driven
development, diagnostics, and break-glass repair.

If admin tasks are needed on an MSI-owned workstation, register them in
installed-only mode so Task Scheduler references the installed product path
instead of a source checkout:

```powershell
cd "C:\Program Files\Arcane EDR"
.\scripts\repair-msi-local-config.cmd -RegisterAdminTasks
```

## Explicit Live Update

The operator can still request a live update outside a tag. Treat that as an
exception, and state that the live service will be changed before running the
publish/restart task.

## Service Restarts

Restart the live service only when one of these is true:

- A tagged release is being deployed.
- A config change needs the service to reload.
- A service behavior test explicitly requires a restart.
- The operator directly asks for a restart.

Do not restart the service for ordinary documentation edits or roadmap changes.

## Config Preservation

Publishing must preserve live machine-specific files unless replacement is
explicitly requested:

```text
C:\Program Files\Arcane EDR\config\ArcaneEDR.config
C:\Program Files\Arcane EDR\config\Deployment.config
```

If a previous source/script install left this folder behind, it is not part of
the MSI-owned runtime path after verification passes:

```text
C:\Applications\ArcaneEDR
```

Machine-specific values, secrets, recipient addresses, local paths, and local
deployment choices should stay in ignored local config or environment variables,
not tracked source files.
