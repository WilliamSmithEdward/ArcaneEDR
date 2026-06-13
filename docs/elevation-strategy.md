# Elevation Strategy

Arcane EDR uses constrained scheduled tasks as the preferred elevation model for
admin-only maintenance from a normal Codex desktop session.

## Decision

Do not rely on running the Codex desktop app as Administrator for routine
Arcane EDR work. The current Codex desktop install is a Store/MSIX packaged app,
and Windows does not reliably launch it with an elevated token.

Instead, use named scheduled tasks under `\ArcaneEDR\` that run with highest
privileges and perform only approved operations.

## Approved Tasks

- `PublishRestart`: stop service if installed, build from source, publish while
  preserving live config, then restart the service. When tasks are registered
  in installed-only mode, this restarts the installed payload without source
  build/publish.
- `InstallService`: publish, install the Windows service, configure service
  recovery, then start it.
- `UninstallService`: stop and remove the Windows service.
- `InstallSysmon`: install or update Sysmon from the published `tools` folder.
- `ValidateAdmin`: run `ArcaneEDR.exe --validate-config` elevated.

## Setup

Run once from elevated PowerShell:

```powershell
cd <repo-root>
.\scripts\install-admin-tasks.cmd
```

For an MSI-owned install that should not depend on the source checkout:

```powershell
cd "C:\Program Files\Arcane EDR"
.\scripts\repair-msi-local-config.cmd -RegisterAdminTasks
```

## Usage

From a normal shell:

```powershell
.\scripts\run-admin-task.cmd -TaskName ValidateAdmin
.\scripts\run-admin-task.cmd -TaskName PublishRestart
```

Use the `.cmd` wrappers when possible. They invoke PowerShell with
`-ExecutionPolicy Bypass -File`, which avoids local execution-policy blocks
without changing the machine-wide policy.

## Verification

After setup, validate the bridge from a normal shell:

```powershell
.\scripts\run-admin-task.cmd -TaskName ValidateAdmin
```

A successful run reports `LastTaskResult: 0`, writes
`SUCCESS ValidateAdmin`, and records elevated validation output in
`%ProgramData%\ArcaneEDR\AdminTasks\ValidateAdmin.log`.

## Logs

Task output is written to:

```text
%ProgramData%\ArcaneEDR\AdminTasks\<TaskName>.log
```

## Removal

Run from elevated PowerShell:

```powershell
cd <repo-root>
.\scripts\uninstall-admin-tasks.cmd
```

## Rationale

This keeps elevation narrow and auditable. A normal Codex session can trigger
only predefined Arcane EDR maintenance tasks instead of receiving a general
administrator token.
