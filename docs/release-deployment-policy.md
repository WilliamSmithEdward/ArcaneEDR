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

Default source folder:

```text
C:\Development\ArcaneEDR
```

Default live application folder:

```text
C:\Applications\ArcaneEDR
```

Default log folder:

```text
C:\Security
```

## Normal Development

During normal development:

```powershell
cd C:\Development\ArcaneEDR
.\scripts\build.cmd
.\bin\ArcaneEDR.exe --validate-config
```

This validates source changes without touching the live service.

Documentation-only changes do not require build, publish, service restart, or
redeploy.

## Tagged Release Deployment

When a new release tag is intentionally cut, the release process can publish the
new build to the live application folder and restart the service.

Preferred deployment path:

```powershell
cd C:\Development\ArcaneEDR
.\scripts\run-admin-task.cmd -TaskName PublishRestart
```

This uses the constrained admin task bridge and preserves live machine-specific
config by default.

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
C:\Applications\ArcaneEDR\config\ArcaneEDR.config
C:\Applications\ArcaneEDR\config\Deployment.config
```

Machine-specific values, secrets, recipient addresses, local paths, and local
deployment choices should stay in ignored local config or environment variables,
not tracked source files.
