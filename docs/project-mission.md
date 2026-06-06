# Project Mission

Arcane EDR exists to make unattended agent workstations safer.

The project is built for environments where autonomous or semi-autonomous agents
need broad local capability, fast iteration, and access to current tools, but
where the owner still wants strong guardrails against supply-chain compromise,
remote access tooling abuse, credential misuse, persistence, and suspicious
egress.

## Operating Philosophy

- Stay close to the host. Use Windows-native telemetry, local logs, Sysmon when
  available, and simple files that can be inspected without an enterprise
  console.
- Prefer practical control over perfect coverage. The goal is to reduce risk on
  real agent boxes, not to pretend to be a complete commercial EDR.
- Keep the owner in control. Local config should define recipients, thresholds,
  response modes, allowlists, paths, privacy settings, and optional integrations.
- Support bleeding-edge work. The system should tolerate active development,
  automation, package installs, browser use, AI tooling, and rapid changes
  without drowning the owner in false positives.
- Avoid enterprise prerequisites. Arcane should not require a paid EDR, SIEM,
  MDM, cloud SOC, domain deployment, or long procurement path to be useful.
- Make elevation deliberate. Admin actions should use constrained, auditable
  workflows instead of giving general-purpose tools permanent administrator
  power.
- Treat privacy as a product boundary. External analysis and notification
  payloads should be compact, bounded, optional, and redacted by default.

## Non-Goals

- Arcane is not a packet sniffer.
- Arcane is not a replacement for Microsoft Defender, Sysmon, Windows Firewall,
  backups, patching, or least-privilege hygiene.
- Arcane is not a full enterprise EDR or SIEM.
- Arcane is not intended to silently remediate broad classes of activity without
  explicit response configuration and audit logs.

## Version 1 North Star

For `v1.0.0`, Arcane should be a reliable safety layer for unattended agent
hosts: easy to install, safe to upgrade, quiet enough to leave running, explicit
about privacy, useful without enterprise infrastructure, and capable of alerting
quickly when behavior starts to look like RAT activity, persistence, or
untrusted egress.
