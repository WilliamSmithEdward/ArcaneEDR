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

Overall status: partially conformant. The GUI is now a credible operator console
with native WinUI controls, persistent tray access, help entry points, and
stronger confirmation around risky actions. It is not yet a fully polished
end-user application because responsive layout, command state feedback, table
ergonomics, and formal accessibility verification still need focused work.

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

### Partially Conforms

- Responsive layout: several pages still rely on fixed multi-column grids. This
  is most visible in Alerts filters/table, Maintenance command rows,
  Configuration guided cards, About two-column cards, and Overview stat cards.
  These layouts may crowd or clip at narrow window widths, high DPI, or larger
  text settings.
- Alert table ergonomics: the current table is a `ListView` with aligned grid
  columns. It supports filtering and sorting through external controls, but it
  does not offer resizable columns, keyboard-sortable headers, column chooser,
  persistent saved views, or an adaptive card/list view at narrow widths.
- Command feedback: many commands await background CLI work, but there is no
  consistent progress ring, disabled-running state, cancellation path, or
  success/failure status bar pattern.
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
  and Advanced Keys covers the rest. A schema-driven config model would make it
  easier to guarantee that every supported config key has a control type,
  validation rule, help text, default, and save behavior.
- Notification-area implementation: the tray icon uses `Shell_NotifyIcon` and
  sets version 4 behavior, but it does not yet use a stable GUID identity or
  `LoadIconMetric` for optimal high-DPI icon selection.

### Does Not Yet Conform

- The GUI has not completed a formal end-user accessibility test matrix.
- The GUI has not completed a visual responsive sweep across small, medium,
  large, high-DPI, and increased-text Windows settings.
- The GUI does not yet provide consistent in-app command state feedback for all
  long-running or side-effecting commands.
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

## Recommended Next GUI Work

1. Build a reusable command execution UX:
   status bar, progress ring, disabled initiating button, timeout text,
   cancellation where safe, and consistent success/failure presentation.
2. Convert fixed grids to adaptive layouts:
   wrap filter bars, stack card groups below breakpoints, and use a compact
   alert list-detail layout at narrow widths.
3. Replace the faux alert/config tables with a stronger table pattern:
   keyboard-sortable headers, column sizing, saved filters, row details, and
   export/copy affordances.
4. Add field-level help:
   small help buttons beside complicated or dangerous settings, with concise
   explanations, safe defaults, expected effect, and rollback path.
5. Make configuration schema-driven:
   one metadata source for key name, category, default, type, validation,
   danger level, help text, repo default, and local override behavior.
6. Finish the accessibility pass:
   Narrator labels, tab order, focus visibility, high contrast, scaled text,
   keyboard-only operation, status announcements, and non-color-only severity.
7. Improve notification-area robustness:
   stable GUID identity, high-DPI icon loading, and possibly a small Help menu
   item that opens the relevant GUI help page.

## Ship Judgment

The v0.8.5 GUI is acceptable as an operator-console preview with MSI install,
self-contained WinUI runtime, persistent tray access, and meaningful guardrails.
For a smooth end-user product experience, the next release should prioritize
responsive layout and command-state feedback before adding more features.
