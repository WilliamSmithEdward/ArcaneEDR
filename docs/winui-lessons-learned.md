# WinUI Lessons Learned

This note records practical lessons from building the Arcane EDR `v0.8.x`
operator console with WinUI 3, Windows App SDK, .NET 10, and WiX MSI packaging.
It is intended as a durable implementation guide, not a complete WinUI tutorial.

## Current Stack

Arcane uses WinUI 3 through the Windows App SDK for the operator GUI. This is
the right default for a Windows-only native desktop app that wants modern
Fluent controls, Windows 10/11 support, and a C#/.NET codebase.

Current project posture:

- UI framework: WinUI 3.
- SDK/runtime package: `Microsoft.WindowsAppSDK`.
- Runtime target: `.NET 10`, `net10.0-windows10.0.26100.0`.
- Deployment: self-contained GUI payload under the MSI-owned product folder.
- Installer: WiX MSI.
- Standard install root: `%ProgramFiles%\Arcane EDR`.

As of 2026-06-11, Microsoft positions WinUI as the recommended native UI
framework for modern Windows apps. Check the Windows App SDK downloads page
before version upgrades, because the stable SDK line moves independently of
Windows itself.

References:

- Microsoft WinUI 3: https://learn.microsoft.com/windows/apps/winui/winui3/
- Windows app platform overview: https://learn.microsoft.com/windows/apps/get-started/
- Windows App SDK downloads: https://learn.microsoft.com/windows/apps/windows-app-sdk/downloads

## Framework Choice

For Arcane, prefer WinUI 3 over WPF, WinForms, UWP, Electron, or a browser shell.
The product is a local Windows security console, so native Windows controls,
Windows service integration, per-machine MSI install, and standard user
execution matter more than cross-platform reach.

Use .NET MAUI only if cross-platform becomes a real requirement. On Windows,
MAUI uses WinUI underneath, so it would add abstraction without improving the
Windows-first operator experience.

## Deployment Lessons

Self-contained GUI deployment is worth the larger payload. Framework-dependent
WinUI builds can prompt for missing Windows App Runtime components, which is a
bad first-run experience for a security tool. The MSI should install a GUI that
starts without asking the operator to install another runtime.

Keep the GUI and service in the same MSI-owned product root:

```text
C:\Program Files\Arcane EDR\bin\ArcaneEDR.exe
C:\Program Files\Arcane EDR\gui\ArcaneEDR.Gui.exe
C:\Program Files\Arcane EDR\config\
```

Do not keep split runtime paths such as `C:\Applications\ArcaneEDR` after MSI
ownership is established. Product files belong under Program Files; mutable
evidence and local state belong under the documented data/log paths.

The publish/MSI path must close running GUI instances before copying GUI DLLs.
Otherwise `ArcaneEDR.Gui.dll` can remain locked and produce partial publishes.

WinUI `*.xbf` files and `ArcaneEDR.Gui.pri` are part of the executable GUI
payload, not optional resources. A newer `ArcaneEDR.Gui.dll` beside stale
`Pages\*.xbf` files can make page navigation fail during generated
`Connect(...)` casts. Every GUI build, publish, MSI install, and MSI validation
should run `scripts\test-gui-payload.ps1` so DLL, PRI, and XBF resources are
present and from the same build window.

## GUI Process Posture

Run the GUI as a normal user app. Do not make the GUI permanently elevated.
Use constrained admin tasks or MSI elevation for service install, publish,
restart, and other privileged operations.

The GUI should be a client of the product, not a second implementation of the
product. Prefer shared config logic, structured CLI output, and local state
files over parsing human text or duplicating service behavior.

Page navigation must cancel stale async work. WinUI pages can unload while a
refresh command is still awaiting process output or local file reads. Every
page-level refresh that updates XAML after an `await` should have an unload
cancellation path and a generation/current-page guard before touching controls.
Log and handle XAML/navigation exceptions so recoverable refresh failures do not
become process exits.

## Scroll Handling

WinUI scroll behavior deserves deliberate treatment. The final stable pattern
for Arcane is:

- Disable horizontal scroll/rail on page surfaces unless a view truly needs it.
- Disable scroll chaining and inertia on page-owned scroll surfaces.
- For top-level page hosts, disable native `VerticalScrollMode` and route
  vertical wheel/trackpad input with a page-scoped attached behavior.
- Move page hosts with clamped `ChangeView(..., disableAnimation: true)` calls.
  Clamp every step to `0..ScrollableHeight`, not only edge events.
- Add a short edge lock after reaching the top or bottom. Precision touchpads
  and high-resolution mouse wheels can send tiny momentum-tail deltas in the
  opposite direction after the visual edge is reached; without a brief lock,
  the page can drift a few pixels away from the edge and snap back.
- Avoid nested read-only `TextBox` scroll regions for large output. Prefer
  selectable wrapping `TextBlock` content inside the page scroll host.
- Keep internal scrolling only where it is clearly expected, such as editable
  policy JSON or alert tables.
- Do not attach a global wheel router to the app root. It can route wheel input
  between unrelated scroll regions and cause bounce or jump behavior.
- Make scroll content hit-testable. A transparent background on the top-level
  page content lets the attached behavior receive wheel input over padding and
  gaps.
- Avoid `CancelDirectManipulations()` in the wheel path. It can interact badly
  with WinUI unload/navigation timing and produce XAML-native crashes.

Important implementation notes:

- `ScrollViewer` is sealed in WinUI, so do not subclass it.
- Use an attached behavior for page-level scroll policy.
- Register the edge handler on the `ScrollViewer.Content`, not globally on the
  window root.
- The attached behavior should detach on `Unloaded`, ignore detached XAML
  (`XamlRoot == null`), and log/swallow wheel-route exceptions so input handling
  does not become a crash path.
- Keep nested scroll areas deliberate. If a nested `ScrollViewer` can still
  scroll in the current direction, let it handle the gesture. If it is at its
  edge, let the page-scoped behavior take over.

Regression coverage should include a focused scroll oracle. Arcane uses
`scripts\test-gui-scroll.cmd` to protect the intended page-scroll structure.

## Layout Lessons

WinUI layouts need explicit constraints in operator tools. Avoid unconstrained
wide content, especially command output, JSON, paths, remote endpoint metadata,
and alert details.

Good defaults:

- Wrap long text by default.
- Use `TextTrimming` in dense table columns.
- Constrain fixed-format panels with stable min/max sizes.
- Keep page sections unframed where possible; use cards for repeated items,
  modal content, or genuinely bounded panels.
- Avoid nested cards.
- Use native controls such as `NavigationView`, `TabView`, `ListView`,
  `ComboBox`, `CheckBox`, `ToggleSwitch`, and `InfoBar` instead of custom
  control lookalikes.

## Icons And Branding

Set icons at every user-facing layer:

- executable icon for File Explorer
- title-bar/window icon
- Start menu shortcut icon
- tray icon
- in-app logo assets

Use `.ico` for shell-facing executable and shortcut surfaces. Use PNG assets
for in-app branding where WinUI expects image resources.

## Tray Behavior

The tray icon should be a convenience surface, not a hidden second app. Start
Menu launch should show the GUI immediately and also create the tray icon.

Recommended tray behavior:

- Left click: show or focus the GUI.
- Right click: expose a concise command menu.
- Include commands for overview, alerts, validation, logs/config folders, and
  exit.
- Keep privileged actions behind the same admin-task boundaries as the GUI.

## Help And Dangerous Actions

Security tools need inline help because normal users should not need to infer
the blast radius of maintenance or policy changes.

Use tooltips for compact controls and help buttons for complicated sections.
For actions that can break service health, overwrite config, reset defaults, or
change response posture:

- explain the effect in plain language
- require an explicit checkbox or confirmation
- keep `ResponseMode=AlertOnly` as the safe default
- preserve local evidence even when notification behavior is dampened

## Verification Checklist

Before calling GUI work complete, run:

```powershell
.\scripts\test-gui-scroll.cmd
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\build-gui.ps1 -OutputPath artifacts\gui-check
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\test-fixtures.ps1
.\scripts\build-msi.cmd
.\scripts\test-msi-validation.cmd -RunAdminValidation
```

For local deployment validation:

```powershell
Get-Process -Name ArcaneEDR.Gui -ErrorAction SilentlyContinue | Stop-Process -Force
.\scripts\run-admin-task.cmd PublishRestart
Start-Process -FilePath "C:\Program Files\Arcane EDR\gui\ArcaneEDR.Gui.exe"
Get-CimInstance Win32_Service -Filter "Name='ArcaneEDR'"
```

Manual GUI checks still matter. Automated UI inspection may not expose every
WinUI visual tree or scroll state from a non-interactive shell, so confirm
real pointer/trackpad behavior in the running installed GUI.

Prefer structured CLI output for GUI bindings. Human console text is useful for
operators, but GUI code should consume `--json` outputs for validation, health,
alert volume, agent activity, incidents, response firewall state, policy
inspection, and report preview when those outputs are available. Keep human
text fallback during upgrade windows so the GUI can survive a partially updated
install.

Overview should be an operator note, not a diagnostic dump. Put the plain
status, validation blockers/warnings, and next action first; keep raw evidence
and timestamps one level lower.

For complex configuration surfaces, keep operator-facing choices in one
catalog or metadata model. Arcane's Policy tab uses a shared policy scope
catalog for entry type labels, file sections, default actions, sort order, and
wizard/editor dropdowns. Avoid parallel hard-coded lists in XAML, page code,
and store code; they drift quickly and make "unified" models feel fragmented.

## Upgrade Discipline

Stay on stable Windows App SDK releases for operator builds. Preview or
experimental SDKs are useful for research only.

Before upgrading the Windows App SDK:

- read Microsoft release notes
- build the self-contained GUI
- rebuild MSI
- launch from the MSI-owned Program Files path
- test tray behavior
- test title-bar and shell icons
- test all top-level page scrolling
- test alerts table scrolling
- test editable JSON text areas

Do not assume an SDK upgrade is just a package bump. WinUI behavior can change
in details such as scrolling, packaging, resource lookup, and generated XAML
code.
