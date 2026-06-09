# Remote Endpoint Policy

Remote endpoint policy is the single ordered JSON surface for remote allow,
trust, block, and critical country/owner/domain/CIDR decisions.

Use `RemoteEndpointPolicyFile` in `ArcaneEDR.config` to point Arcane at the
policy file. The tracked default is `config\remote-endpoint-policy.example.json`;
host-specific tuning should use the ignored `config\remote-endpoint-policy.json`.

## Defaults

The default example policy marks these conditions critical:

- RDAP enrichment was attempted, but no country was returned.
- RDAP country is anything other than `US`.

Country is best-effort registry data, not proof of physical origin. RDAP
enrichment discloses investigated remote IPs to the configured RDAP lookup
service.

## Evaluation

Policy entries are evaluated from top to bottom. The first enabled entry that
matches wins. Put narrow block or critical entries above broader allow or trust
entries.

Supported actions:

- `critical`: create `NET-REMOTE-POLICY-CRITICAL`.
- `block`: create `NET-REMOTE-POLICY-BLOCKED`.
- `trust`: lower only clean direct-IP and timing-only network noise from
  expected processes.
- `allow`: skip generic external-remote analysis for the matching endpoint.
- `observe`: match for future/local context without changing analysis.

## Match Fields

Supported match fields:

- `remote_ip`: exact IP or CIDR.
- `process_name`
- `port`: exact port or range such as `443` or `8000-8999`.
- `asn`
- `asn_org`
- `owner`
- `domain`
- `rdns`
- `dns_name`
- `sni_hostname`
- `resolved_domain`
- `registrable_domain`
- `country`
- `country_not`
- `country_missing`
- `text_contains`

Text fields use case-insensitive contains matching by default. Prefix an entry
with `regex:` or `re:`, or wrap it as `/pattern/`, for regex matching.
Use JSON arrays for multiple values; strings are treated as one exact policy
entry so regex patterns can safely contain commas.

`--validate-config` fails on unsupported actions, invalid CIDRs, malformed port
ranges, and invalid regex entries before the service uses the policy.

## Example

```json
{
  "policies": [
    {
      "id": "critical-country-missing",
      "enabled": true,
      "action": "critical",
      "score": 90,
      "reason": "RDAP was attempted but no country was returned.",
      "match": {
        "country_missing": true
      }
    },
    {
      "id": "trust-expected-agent-vendor",
      "enabled": true,
      "action": "trust",
      "reason": "Expected agent backend traffic.",
      "match": {
        "process_name": "codex.exe",
        "owner": "Cloudflare",
        "port": 443
      }
    }
  ]
}
```
