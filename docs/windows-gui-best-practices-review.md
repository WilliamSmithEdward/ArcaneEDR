# Windows GUI Best Practices Review

This document records the GUI guidance used for the Arcane EDR `v0.8.2`
operator-console sweep. A practice is treated as adopted only when it is
supported by three independent sources or by one Windows-platform source plus
two broader UX/accessibility sources.

## Sources

- Microsoft Learn, [Design Windows apps](https://learn.microsoft.com/en-us/windows/apps/design/)
- Microsoft Learn, [Windows application development best practices](https://learn.microsoft.com/en-us/windows/apps/get-started/best-practices)
- Microsoft Learn, [Navigation design basics](https://learn.microsoft.com/en-us/windows/apps/design/basics/navigation-basics)
- Microsoft Learn, [NavigationView](https://learn.microsoft.com/en-us/windows/apps/develop/ui/controls/navigationview)
- Microsoft Learn, [Responsive design techniques](https://learn.microsoft.com/en-us/windows/apps/design/layout/responsive-design)
- Microsoft Learn, [Guidelines for app settings](https://learn.microsoft.com/en-us/windows/apps/design/app-settings/guidelines-for-app-settings)
- Microsoft Learn, [Dialog controls](https://learn.microsoft.com/en-us/windows/apps/develop/ui/controls/dialogs-and-flyouts/dialogs)
- Microsoft Learn, [Accessibility overview](https://learn.microsoft.com/en-us/windows/apps/design/accessibility/accessibility-overview)
- Fluent 2, [Accessibility](https://fluent2.microsoft.design/accessibility)
- W3C, [WCAG 2.2](https://www.w3.org/TR/WCAG22/)
- W3C WAI, [Error Prevention](https://www.w3.org/WAI/WCAG21/Understanding/error-prevention-legal-financial-data.html)
- Nielsen Norman Group, [Consistency and standards](https://www.nngroup.com/articles/consistency-and-standards/)
- Nielsen Norman Group, [Data tables](https://www.nngroup.com/articles/data-tables/)
- Nielsen Norman Group, [Helpful filter categories and values](https://www.nngroup.com/articles/filter-categories-values/)
- Nielsen Norman Group, [Confirmation dialogs](https://www.nngroup.com/articles/confirmation-dialog/)
- IBM Carbon Design System, [Data table usage](https://carbondesignsystem.com/components/data-table/usage/)
- IBM Carbon Design System, [Filtering pattern](https://carbondesignsystem.com/patterns/filtering/)
- Material Design, [Data tables](https://m1.material.io/components/data-tables.html)
- Microsoft Learn, [Windows Installer](https://learn.microsoft.com/en-us/windows/win32/msi/windows-installer-portal)
- Microsoft Learn, [Windows Installer best practices](https://learn.microsoft.com/en-us/windows/win32/msi/windows-installer-best-practices)
- FireGiant WiX Docs, [Major upgrade guidance](https://docs.firegiant.com/wix3/howtos/updates/major_upgrade/)

## Adopted Practices

### 1. Use Native Windows Structure For App Navigation

Verified by Microsoft Navigation basics, Microsoft NavigationView, and NN/g
consistency guidance.

Arcane decision:

- Keep top-level app areas in one `NavigationView`.
- Use a flat structure for Overview, Alerts, Policy, Reports, Configuration,
  Maintenance, About, and Settings.
- Use section-local tabs only for alternate views of the same task, such as
  Alerts table/volume/raw evidence and Configuration guided/advanced/policy.

### 2. Make The First Screen Actionable

Verified by Microsoft Windows UX guidance, Fluent hierarchy guidance, and NN/g
data-table/task guidance.

Arcane decision:

- Overview must show service state, current signal picture, validation blockers,
  and concrete review priorities.
- Avoid filling Overview with static paths or configuration plumbing; put those
  details in Settings/About/Configuration.

### 3. Keep Settings GUI-Driven But Validate Against The Real Product Config

Verified by Microsoft app-settings guidance, NN/g consistency guidance, and
W3C error-prevention guidance.

Arcane decision:

- Guided settings use toggles, combo boxes, and text fields for high-impact
  options.
- Advanced keys expose every `key=value` runtime/deployment setting, preserving
  source files and comments where possible.
- Save operations create backups and immediately run `--validate-config`.
- Secrets remain environment-variable names only; the GUI must not ask users to
  paste live secret values into tracked or local config.

### 4. Use Tables For Dense Alert Triage

Verified by NN/g data-table guidance, IBM Carbon data-table guidance, and
Material Design data-table guidance.

Arcane decision:

- Alerts use a compact table/list view for scanning and comparison.
- Columns expose time, rule, category, score, country, process, company, and
  title.
- Selection reveals row detail without navigating away from the table.
- Raw JSONL remains available as evidence, but it is not the primary triage UI.

### 5. Put Filters Near The Data And Make Their Meaning Predictable

Verified by NN/g filter guidance, IBM Carbon filtering guidance, and Microsoft
Windows command/control guidance.

Arcane decision:

- Alerts filters sit above the table and include lookback, severity, category,
  external-threshold, search, sort field, and direction.
- Filter names use Arcane's operator language rather than generic UI jargon.
- The external-threshold filter is bound to `MinimumEmailScore`, so the table
  reflects live configuration semantics.

### 6. Avoid Nested Scroll Traps

Verified by Microsoft responsive/layout guidance, W3C focus-order/focus-visible
requirements, and NN/g table/scanning guidance.

Arcane decision:

- Read-only console output is rendered as selectable `TextBlock` content inside
  page-owned scroll surfaces.
- Editable text areas, such as policy JSON, may scroll internally because text
  editing needs a cursor and horizontal movement.
- Pages should not place read-only `TextBox` controls inside a larger
  `ScrollViewer`.

### 7. Preserve Accessibility Fundamentals

Verified by Microsoft accessibility overview, Fluent accessibility guidance,
and WCAG 2.2.

Arcane decision:

- Prefer WinUI controls with built-in automation peers, focus behavior, and
  keyboard support.
- Keep visible labels/headers for filters and settings.
- Avoid icon-only commands unless a tooltip explains the action.
- Use theme resources instead of hard-coded colors so high contrast and theme
  changes remain plausible.

### 8. Guard Destructive Or High-Impact Actions

Verified by Microsoft dialog guidance, NN/g confirmation-dialog guidance, and
W3C error-prevention guidance.

Arcane decision:

- Reset local config requires an explicit checkbox and creates backups.
- Active response controls stay visible but conservative; `AlertOnly` remains
  the safe default.
- Future destructive service or response actions should use `ContentDialog`
  with a safe cancel/close path and specific button text.

### 9. Prefer MSI For Operator Deployment

Verified by Microsoft Windows Installer documentation, Microsoft Windows
Installer best-practices guidance, and FireGiant WiX major-upgrade guidance.

Arcane decision:

- MSI should become the normal local install/upgrade/uninstall path once the
  GUI/MSI track is validated.
- Admin publish scripts remain documented as developer and break-glass tools,
  not the primary operator workflow.

## Sweep Checklist

- [x] Overview: actionable review priorities, no text/image overlap, no
  config-path clutter.
- [x] Alerts: tabbed table/volume/raw evidence, table filters bound to config,
  sortable scan columns, selected-row detail.
- [x] Policy: inspect/preview/open workflow remains available; the Policy tab
  provides structured create/read/update/delete, header sorting, hide-disabled
  filtering, move up/down ordering, and a guided Add policy wizard. The wizard
  and setting editor consume the same policy metadata catalog as the rest of the
  Policy tab. Raw policy JSON remains available as an escape hatch.
- [x] Reports: preview/JSON/send are available and output is scroll-safe.
- [x] Configuration: guided controls, advanced key editor, policy JSON editor,
  validation, reset with backup.
- [x] Maintenance: maintenance markers, admin bridge tasks, poll-once, test
  notifications, AI payload/test utilities, incidents, agent activity, response
  firewall ledger, support bundle.
- [x] Settings/About: theme and environment/context details only; no primary
  operational tasks hidden here.
- [x] Packaging: self-contained .NET 10 / WinUI payload; title-bar icon and app
  assets included; MSI is preferred for operator deployment.

## Implementation Notes

- Read-only output regions were converted from nested read-only `TextBox`
  controls to selectable text inside page-owned scroll surfaces.
- The left navigation header now uses a shield-only logo with a fixed logo lane
  so text cannot overlap the image.
- The Overview masthead uses a larger product logo and separates the image,
  title, and actions into distinct grid columns.
- Alerts now uses local JSONL parsing for operator rows and keeps raw evidence
  as a secondary tab.
- Policy now uses a shared scope catalog for entry type labels, order, section
  names, default actions, setting keys, match-field choices, alert-derived
  defaults, and wizard/editor dropdowns. The GUI policy oracle compares catalog
  keys with `config\arcane-policy.example.json` so default configuration and GUI
  affordances stay aligned.
- The second polish pass constrained the navigation pane, stretched Maintenance
  commands into predictable columns, lowered the default Alerts metadata height
  so the table remains the primary scan surface, and moved Reports preview away
  from markdown-looking section underline artifacts.
- The third polish pass removed stray add-tab buttons from fixed tab sets,
  replaced silent ellipses in scan-heavy rows with hover text, shortened Policy
  metrics so cards read as metrics instead of clipped sentences, and reused one
  metric text style for Overview and Policy.
- Per-user table/filter preferences now save without reapplying Windows startup
  registration. Startup registration remains owned by the Settings page and the
  MSI-owned Program Files GUI launch path.
- Configuration saves runtime/deployment config through GUI controls, creates
  timestamped backups, and validates with Arcane's real CLI validator.
- High-impact maintenance actions use confirmation dialogs with safe cancel
  behavior.
