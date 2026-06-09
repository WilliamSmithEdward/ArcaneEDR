# Remote Endpoint Policy

Remote endpoint policy is the single ordered JSON surface for remote allow,
trust, block, and critical country/owner/domain/CIDR decisions.

Remote endpoint entries live in the `remote_endpoint_policies` section of the
unified policy file configured by `PolicyFile`. The tracked default is
`config\arcane-policy.example.json`; host-specific tuning should use an ignored
local copy.

## Defaults

The default example policy treats these conditions differently:

- Arcane EDR service self-traffic: allow before generic network analysis.
- Known major provider owner context, such as Microsoft or Cloudflare: trust
  before non-US country escalation.
- Local country-block enrichment was enabled, no country was found, and no
  DNS/domain identity was available: critical. The same applies when configured
  geolocation providers such as `ip-api` or `ipwhois` are tried and still no
  country or DNS/domain identity is available.
- Country remains unavailable, but some identity context is present or local
  country/geolocation enrichment is not enabled: observe and add review weight.
- RDAP country is anything other than `US`: critical.

Country is best-effort registry data, not proof of physical origin. RDAP
enrichment discloses investigated remote IPs to the configured RDAP lookup
service. Optional external geolocation providers also disclose investigated
remote IPs to those providers.

Country-unavailable context should not always be a standalone critical finding.
Arcane escalates an observed country-missing policy to critical when it is
paired with a first-seen app/remote-IP pair or another stronger suspicious
signal for that endpoint. When local country-block enrichment is enabled, a
destination that has neither country nor DNS/domain identity after enabled
enrichment is also critical.

## Local Country Blocks

`EnableRemoteEndpointCountryBlockEnrichment=true` enables a local country
lookup before RDAP. Point `RemoteEndpointCountryBlocksDirectory` at an extracted
`ipverse/country-ip-blocks` tree, such as a directory containing
`country\us\ipv4-aggregated.txt` and `country\us\ipv6-aggregated.txt`.

Arcane reads the files locally and does not download country data at runtime.
Country-block data is administrative/delegation context; keep treating it as a
triage signal, not proof of physical server location.

## Optional Geolocation Providers

`EnableRemoteEndpointIpApiGeolocation=true` enables the configurable
`ip-api.com` hook. `EnableRemoteEndpointIpWhoisGeolocation=true` enables the
configurable `ipwhois.io`/`ipwho.is` hook. Both are disabled in tracked repo
config. Their free endpoints are for non-commercial use only; commercial use
requires the provider's paid/commercial plan.

These providers are used as bounded enrichment sources, not as blocking
dependencies. `RemoteEndpointGeoProviderMaxLookupsPerPoll` caps combined
`ip-api` and `ipwhois` requests per poll. Arcane tries local country blocks
first, then RDAP for registry owner/ASN context, then these providers only when
country or useful owner/ASN context is still missing. If a provider is enabled
but the cap prevents a lookup, Arcane records country lookup status as
`deferred-after-*` rather than `missing-after-*`, so the default
fully-unresolved critical policy does not fire before the enabled source has
actually been tried.

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
- `observe`: add review weight to alerts already generated for the endpoint
  without creating a standalone policy alert. When paired with first-seen
  app/IP context or stronger suspicious activity, observe entries can escalate
  to `NET-REMOTE-POLICY-CRITICAL`.

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
- `country_lookup`
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
  "remote_endpoint_policies": [
    {
      "id": "critical-country-unresolved-after-local-geo-and-dns",
      "enabled": true,
      "action": "critical",
      "score": 90,
      "reason": "Country and DNS/domain identity were unavailable after enabled enrichment.",
      "match": {
        "country_lookup": "regex:^missing-after-(country-blocks|ip-api|ipwhois).*-dns$"
      }
    },
    {
      "id": "observe-country-unavailable",
      "enabled": true,
      "action": "observe",
      "score": 10,
      "reason": "Country remains unavailable, but this is context rather than standalone critical evidence.",
      "match": {
        "country_lookup": [
          "missing-after-rdap",
          "missing-after-rdap-dns",
          "regex:^missing-after-(country-blocks|ip-api|ipwhois).*$"
        ]
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
