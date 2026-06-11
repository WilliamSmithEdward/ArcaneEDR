# Unified Policy

Arcane uses one JSON policy file for allow, block, trust, response, remote
endpoint, and structured alert tuning decisions. Configure it with `PolicyFile`
in `ArcaneEDR.config`.

The tracked default is `config\arcane-policy.example.json`. For host-specific
tuning, copy it to an ignored local policy file and point `PolicyFile` there.

## Sections

- `allowlists`: expected listening ports, expected outbound ports, process
  specific outbound ports, trusted processes, allowed DNS resolvers, allowed
  remote countries, and trusted persistence name/path/signer context.
- `blocklists`: blocked domains and blocked hashes.
- `response_policy`: active-response allow/block/protected-process gates.
- `remote_endpoint_policies`: ordered remote allow, trust, block, critical, and
  observe rules. First enabled match wins.
- `detection_policies`: local alert tuning rules such as score changes,
  external suppression, force alert, and tag-only entries.

Normal thresholds, collector toggles, retention, enrichment provider settings,
and response mode remain in `ArcaneEDR.config`.

## Defaults

The default policy:

- Allows Arcane EDR service self-traffic before generic network analysis.
- Suppresses external email for Codex-launched PowerShell web checks to known
  major provider infrastructure while preserving local RAT/LOLBin evidence.
- Keeps service lifecycle notifications eligible for external delivery; rate
  limits do not block clean starts, clean stops, crash recovery, or daily
  summaries.
- Trusts known major provider remote identity inside an allowed country for
  clean network-shape dampening. Country alone does not lower score.
- Treats countries in `allowlists.allowed_remote_countries` as acceptable
  country context and avoids country-only escalation.
- Escalates fully unresolved country plus missing DNS/domain identity after
  enabled local/provider enrichment.
- Treats ordinary country-unavailable context as an observe score enhancer.

Use `--validate-config` after editing the policy file. Use `--policy-preview`
to preview `detection_policies` against recent alerts or samples before relying
on host-specific tuning.
