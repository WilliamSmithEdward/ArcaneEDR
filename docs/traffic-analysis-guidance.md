# Traffic Analysis Guidance Used

This monitor is a lightweight host-level control, not a replacement for an EDR,
SIEM, firewall, DNS security product, or packet inspection platform. The rules
were selected to match recurring recommendations from enterprise security
vendors while staying feasible with local Windows flow visibility.

## Vendor-Aligned Patterns

- Normalize flow-like records and enrich alerts with process, IP, port, protocol,
  and timestamp context.
- Treat egress control as equally important as ingress control.
- Alert on unexpected inbound exposure and new local listeners.
- Alert on suspicious port usage, port misuse, and high-risk egress ports.
- Alert on connection bursts and scan-like fan-out.
- Alert on low-jitter repeated external connections that may indicate beaconing.
- Support explicit IP/CIDR indicators for known-bad destinations.
- Support authorized DNS resolver enforcement.
- Keep alert thresholds and allowlists tunable to reduce alert fatigue.

## Sources

- Microsoft Sentinel Traffic Analytics integration:
  https://learn.microsoft.com/en-us/azure/network-watcher/traffic-analytics-sentinel
- Palo Alto Networks firewall best practices:
  https://www.paloaltonetworks.com/cyberpedia/firewall-best-practices
- Cisco DNS best practices and attack identification:
  https://sec.cloudapps.cisco.com/security/center/resources/dns_best_practices
- Elastic Network Beaconing Identification:
  https://www.elastic.co/docs/reference/integrations/beaconing/
- Microsoft Defender for Endpoint indicators:
  https://learn.microsoft.com/en-us/defender-endpoint/indicators-overview
