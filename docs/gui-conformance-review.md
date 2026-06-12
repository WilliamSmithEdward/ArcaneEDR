# Arcane EDR GUI Conformance Review

Review date: 2026-06-11

Scope: `src/ArcaneEDR.Gui`, including shell navigation, overview, alerts, policy,
reports, configuration, maintenance, settings, about, and the notification-area
icon added for v0.8.5. This review is based on source inspection, release build
validation, and a launch smoke test. It is not a substitute for a formal
accessibility lab pass with Narrator, keyboard-only operation, high contrast,
and scaled text.

## Source-Backed Criteria

The general GUI criteria below were checked against at least three independent
sources: Microsoft Windows/WinUI/Fluent guidance, W3C WCAG 2.2, and NN/g
usability heuristics. Windows notification-area implementation details are
Windows-specific and therefore lean primarily on Microsoft Shell guidance.

- Native Windows patterns and consistency:
  [Windows app design](https://learn.microsoft.com/en-us/windows/apps/design/),
  [Windows controls and patterns](https://learn.microsoft.com/en-us/windows/apps/develop/ui/controls/),
  [NavigationView](https://learn.microsoft.com/en-us/windows/apps/develop/ui/controls/navigationview),
  [NN/g consistency and standards](https://www.nngroup.com/articles/consistency-and-standards/).
- Layout, hierarchy, and responsive behavior:
  [Windows layout guidance](https://learn.microsoft.com/en-us/windows/apps/design/basics/content-basics),
  [Windows responsive design](https://learn.microsoft.com/en-us/windows/apps/design/layout/responsive-design),
  [Fluent 2 layout](https://fluent2.microsoft.design/layout),
  [WCAG 2.2](https://www.w3.org/TR/WCAG22/).
- Error prevention, user control, and risky actions:
  [ContentDialog](https://learn.microsoft.com/en-us/windows/windows-app-sdk/api/winrt/microsoft.ui.xaml.controls.contentdialog),
  [Windows dialogs](https://learn.microsoft.com/en-us/windows/apps/develop/ui/controls/dialogs-and-flyouts/dialogs),
  [NN/g heuristics](https://www.nngroup.com/articles/ten-usability-heuristics/).
- Help, discoverability, and nonintrusive guidance:
  [Tooltips](https://learn.microsoft.com/en-us/windows/apps/develop/ui/controls/tooltips),
  [Teaching tips](https://learn.microsoft.com/en-us/windows/apps/develop/ui/controls/dialogs-and-flyouts/teaching-tip),
  [InfoBar](https://learn.microsoft.com/en-us/windows/apps/develop/ui/controls/infobar),
  [WCAG consistent help](https://www.w3.org/TR/WCAG22/).
- Accessibility baseline:
  [Fluent accessibility](https://fluent2.microsoft.design/accessibility),
  [WCAG 2.2](https://www.w3.org/TR/WCAG22/),
  [Windows controls and patterns](https://learn.microsoft.com/en-us/windows/apps/develop/ui/controls/).
- Notification-area behavior:
  [Notifications and the notification area](https://learn.microsoft.com/en-us/windows/win32/shell/notification-area),
  [Shell_NotifyIcon](https://learn.microsoft.com/en-us/windows/win32/api/shellapi/nf-shellapi-shell_notifyicona),
  [Windows notification-area UX guidance](https://learn.microsoft.com/en-us/windows/win32/uxguide/winenv-notification).

## Current Assessment

Overall status: mostly conformant for the local operator-console goal. The GUI
uses native WinUI controls, persistent tray access, help entry points, stronger
confirmation around risky actions, structured service data where available, and
simple actionable Overview guidance. Remaining gaps are primarily formal
verification gates: clean-VM installer matrix, public signing, and a complete
accessibility/responsive sweep.

### Conforms

- Uses WinUI 3, Fluent theme resources, native `NavigationView`, `TabView`,
  `InfoBar`, `ContentDialog`, `ListView`, `ComboBox`, `ToggleSwitch`, and
  `TextBox` controls instead of custom drawn controls.
- Uses a small, stable left navigation model for top-level sections:
  Overview, Alerts, Policy, Reports, Configuration, Maintenance, About, and
  Settings.
- Keeps the first screen operational rather than promotional. Overview shows
  service state, health, validation blockers, alert counts, and targeted review
  priorities.
- Provides a persistent notification-area icon. Left-click opens/focuses the
  GUI. Right-click exposes common navigation, validation, log/config folder,
  restart, and exit commands.
- Uses local evidence-first language. Alerts, policy, and overview copy make it
  clear that filtered or suppressed external notification is not deleted local
  evidence.
- Adds help dialogs for the most complex sections: Overview, Alerts, Policy,
  Reports, Configuration, and Maintenance.
- Uses confirmation dialogs with safe cancel actions for high-impact operations:
  response-capable config saves, service install, Sysmon install, publish
  restart, uninstall service, test alert, test AI, live daily report, and
  clearing Arcane-managed firewall rules.
- Reset-to-defaults requires an explicit checkbox and writes backups before
  replacing local config.
- Icon-only buttons in the reviewed high-use surfaces now have tooltips and
  accessible names where recently touched.
- Overview gives a plain-language status, validation summary, next action,
  review queue, signal picture, and service rhythm instead of raw diagnostic
  dumps as the first read.
- Long-running configuration, policy, report, and maintenance actions show a
  running message and disable the initiating button while work is in progress.
- Alerts table supports clickable sort headers, sort indicators, resizable
  columns, vertical details resizing, saved per-user view preferences, and CSV
  copy/export of the visible filtered rows.
- Configuration guided controls include field-level tooltips for dangerous or
  privacy-sensitive settings, and Advanced Keys uses metadata for type, risk,
  restart requirement, and privacy notes.

### Partially Conforms

- Responsive layout: several pages still rely on fixed multi-column grids. This
  is most visible in Alerts filters/table, Maintenance command rows,
  Configuration guided cards, About two-column cards, and Overview stat cards.
  These layouts may crowd or clip at narrow window widths, high DPI, or larger
  text settings.
- Alert table ergonomics: the table now supports header sorting, visible
  indicators, resize handles, saved view state, and CSV copy/export. Remaining
  polish is a column chooser and a compact adaptive layout at narrow widths.
- Command feedback: high-use command paths now show running text and disable
  the initiating button. Remaining polish is a global status bar, progress
  ring, and cancellation where cancellation is safe.
- Accessibility: native controls provide a good baseline, but there has not
  been a complete Narrator, keyboard-only, high contrast, 200 percent scaling,
  and text-size pass. Dynamic output panes also need better accessible names and
  live status behavior.
- Help depth: page-level help now exists, but individual high-risk fields and
  provider-specific settings need contextual help affordances. Examples:
  `ResponseMode`, response switches, external provider selection, ip-api and
  ipwhois non-commercial-use hooks, AI API key environment variables, policy
  actions, and deployment paths.
- Configuration coupling: Guided settings cover core runtime/deployment choices,
  Advanced Keys covers the rest, and the GUI now has metadata for type, risk,
  restart, and privacy notes. A future fully generated form could remove the
  remaining manual Guided wiring.
- Policy coupling: the Policy tab now provides structured CRUD, sort/filter,
  move up/down ordering, hide-disabled filtering, and guided policy creation.
  Raw Policy JSON remains an intentional advanced escape hatch.
- Notification-area implementation: the tray icon uses `Shell_NotifyIcon` and
  sets version 4 behavior, but it does not yet use a stable GUID identity or
  `LoadIconMetric` for optimal high-DPI icon selection.

### Does Not Yet Conform

- The GUI has not completed a formal end-user accessibility test matrix.
- The GUI has not completed a visual responsive sweep across small, medium,
  large, high-DPI, and increased-text Windows settings.
- The GUI does not yet provide a global command status bar or cancellation path
  for every long-running command.
- The GUI does not yet fully replace docs/CLI for every advanced workflow in a
  hand-held, step-by-step way. Advanced Keys and Policy JSON remain necessary
  escape hatches.

## Changes Made During This Review

- Added a shared `GuiHelp` dialog helper for consistent help and risk
  confirmations.
- Added page-level help buttons and help copy to Overview, Alerts, Policy,
  Reports, Configuration, and Maintenance.
- Added a warning `InfoBar` to Configuration operating mode settings.
- Added response-risk confirmation before saving response-capable guided
  settings.
- Added live-delivery confirmation before sending a daily report.
- Added explicit confirmations for service install, Sysmon install,
  publish/restart, uninstall service, test alert, test AI, and clearing
  Arcane-managed firewall rules.
- Added more tooltips and accessible names to high-use and icon-only buttons.
- Added a structured Policy tab with a shared policy scope catalog and a single
  Add policy wizard used by both blank policies and alert-derived drafts.

## Recommended Next GUI Work

1. Convert fixed grids to adaptive layouts:
   wrap filter bars, stack card groups below breakpoints, and use a compact
   alert list-detail layout at narrow widths.
2. Add global command status polish:
   status bar, progress ring, timeout text, cancellation where safe, and
   consistent success/failure presentation.
3. Add alert table refinements:
   column chooser, saved named views, and narrow-width card/list layout.
4. Continue configuration metadata work:
   add defaults, validation ranges, repo default visibility, and generated
   controls for more keys.
5. Finish the accessibility pass:
   Narrator labels, tab order, focus visibility, high contrast, scaled text,
   keyboard-only operation, status announcements, and non-color-only severity.
6. Improve notification-area robustness:
   stable GUID identity, high-DPI icon loading, and possibly a small Help menu
   item that opens the relevant GUI help page.

## Ship Judgment

The v0.8.x GUI is acceptable as the operator-console baseline with MSI install,
self-contained WinUI runtime, persistent tray access, meaningful guardrails,
structured read-only command seams, and actionable Overview guidance. The next
product-quality gate should be disposable-VM installer validation plus formal
accessibility and responsive sweeps.
