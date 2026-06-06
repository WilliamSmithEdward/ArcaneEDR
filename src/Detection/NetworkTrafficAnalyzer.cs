using System;
using System.Collections.Generic;
using System.Globalization;
using System.Net;

namespace ArcaneEDR
{
    internal sealed class NetworkTrafficAnalyzer
    {
        private readonly MonitorConfig config;
        private readonly DetectionState state;
        private readonly BaselineStore baselineStore;

        public NetworkTrafficAnalyzer(MonitorConfig config, DetectionState state, BaselineStore baselineStore)
        {
            this.config = config;
            this.state = state;
            this.baselineStore = baselineStore;
        }

        public List<Alert> Analyze(NetworkSnapshot snapshot, DateTime timestampUtc)
        {
            List<Alert> alerts = new List<Alert>();
            Dictionary<string, int> externalConnectionCounts = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
            HashSet<int> tcpListeningPorts = GetTcpListeningPorts(snapshot);

            AnalyzeProcessEvents(snapshot.ProcessEvents, alerts);
            AnalyzeDnsQueries(snapshot.DnsQueries, alerts);

            foreach (NetworkEndpoint endpoint in snapshot.Endpoints)
            {
                if (endpoint.IsTcpListener)
                {
                    AnalyzeTcpListener(endpoint, alerts);
                    continue;
                }

                if (endpoint.IsUdpSocket)
                {
                    AnalyzeUdpSocket(endpoint, alerts);
                    continue;
                }

                if (!endpoint.IsEstablishedTcp)
                {
                    continue;
                }

                AnalyzeTcpConnection(endpoint, tcpListeningPorts, externalConnectionCounts, timestampUtc, alerts);
            }

            AnalyzeConnectionBursts(externalConnectionCounts, alerts);
            return alerts;
        }

        private void AnalyzeProcessEvents(List<SysmonProcessEvent> processEvents, List<Alert> alerts)
        {
            foreach (SysmonProcessEvent process in processEvents)
            {
                string key = "sysmon-process|" + process.RecordId.ToString(CultureInfo.InvariantCulture);
                if (!state.MarkEventSeen(key)) continue;

                bool lolbin = config.LolbinProcesses.Contains(process.ProcessName);
                bool suspiciousCommandLine = FileSystemRules.ContainsAny(process.CommandLine, config.SuspiciousCommandLineTerms);
                bool suspiciousParent = config.SuspiciousParentProcesses.Contains(process.ParentProcessName);
                EncodedCommandFinding encodedCommand = CommandLineRules.FindEncodedCommand(process.CommandLine, config);

                if (ContainsBlockedHash(process.Hashes))
                {
                    alerts.Add(Alert.FromProcessEvent(
                        "PROC-IOC-HASH-MATCH",
                        "Process hash matched blocked indicator",
                        95,
                        "Sysmon process creation included a hash that matched the configured blocked hash list.",
                        "Isolate the host if this was not expected. Preserve the process command line, parent, and binary.",
                        process));
                }

                if (encodedCommand.Detected)
                {
                    alerts.Add(Alert.FromProcessEvent(
                        "PROC-ENCODED-CLI",
                        "Encoded or obfuscated command line detected",
                        85,
                        "Process command line contains encoded or base64-like content. Reason: " + encodedCommand.Reason + ". DecodedPreview: " + encodedCommand.DecodedPreview,
                        "Review the full command line, parent process, and decoded content. Encoded PowerShell/CLI execution is common in RAT staging.",
                        process));
                }

                if (lolbin && suspiciousCommandLine)
                {
                    alerts.Add(Alert.FromProcessEvent(
                        "PROC-LOLBIN-SUSPICIOUS-CMD",
                        "LOLBin started with suspicious command line",
                        85,
                        "A living-off-the-land binary started with command-line content commonly used for download, encoded execution, or stealth.",
                        "Review parent process, command line, and downloaded payloads. This is a common RAT staging pattern.",
                        process));
                }

                if (suspiciousParent && lolbin)
                {
                    alerts.Add(Alert.FromProcessEvent(
                        "PROC-SUSPICIOUS-PARENT-CHAIN",
                        "Suspicious parent spawned network-capable LOLBin",
                        80,
                        "A process commonly abused as an initial access parent spawned a living-off-the-land binary.",
                        "Inspect the parent document/browser/app and the child command line for macro, script, or exploit activity.",
                        process));
                }
            }
        }

        private void AnalyzeDnsQueries(List<DnsQueryEvent> dnsQueries, List<Alert> alerts)
        {
            foreach (DnsQueryEvent dns in dnsQueries)
            {
                string key = "sysmon-dns|" + dns.RecordId.ToString(CultureInfo.InvariantCulture);
                if (!state.MarkEventSeen(key)) continue;

                if (config.IsBlockedDomain(dns.QueryName))
                {
                    alerts.Add(Alert.FromDnsQuery(
                        "DNS-IOC-DOMAIN-MATCH",
                        "DNS query matched blocked domain",
                        95,
                        "DNS query matched the configured blocked domain list.",
                        "Investigate the querying process and any subsequent connections. Consider blocking the domain at DNS/firewall layers.",
                        dns));
                }

                if (config.IsDynamicDnsDomain(dns.QueryName))
                {
                    alerts.Add(Alert.FromDnsQuery(
                        "DNS-DYNAMIC-DNS",
                        "DNS query to dynamic DNS provider",
                        75,
                        "Process queried a domain under a dynamic DNS provider often used for disposable C2 infrastructure.",
                        "Validate whether this destination is business-required. Dynamic DNS is common in RAT infrastructure.",
                        dns));
                }

                if (DomainRules.HasHighEntropyLabel(dns.QueryName))
                {
                    alerts.Add(Alert.FromDnsQuery(
                        "DNS-HIGH-ENTROPY",
                        "High-entropy DNS query",
                        70,
                        "DNS query contains a high-entropy label, which can indicate domain generation, tracking, or tunneling.",
                        "Review the process and query results. Repeated high-entropy queries are suspicious for C2 or DNS tunneling.",
                        dns));
                }

                string baselineKey = dns.ProcessName + "|" + NormalizeDomain(dns.QueryName);
                if (baselineStore.Observe("process-domain", baselineKey) && ShouldAlertOnBaselineNovelty())
                {
                    alerts.Add(Alert.FromDnsQuery(
                        "BASELINE-NEW-PROCESS-DOMAIN",
                        "New process/domain pair",
                        45,
                        "This process queried a domain not previously observed in the local baseline.",
                        "Low severity by itself. Correlate with process lineage, domain age, destination reputation, and unusual egress.",
                        dns));
                }
            }
        }

        private static HashSet<int> GetTcpListeningPorts(NetworkSnapshot snapshot)
        {
            HashSet<int> ports = new HashSet<int>();
            foreach (NetworkEndpoint endpoint in snapshot.Endpoints)
            {
                if (endpoint.IsTcpListener)
                {
                    ports.Add(endpoint.LocalPort);
                }
            }

            return ports;
        }

        private void AnalyzeTcpListener(NetworkEndpoint endpoint, List<Alert> alerts)
        {
            string listenerKey = "tcp-listener|" + endpoint.LocalAddress + "|" + endpoint.LocalPort + "|" + endpoint.ProcessName;
            if (!state.MarkListenerSeen(listenerKey)) return;

            if (!config.AllowedListeningPorts.Contains(endpoint.LocalPort))
            {
                alerts.Add(Alert.FromEndpoint(
                    "NET-LISTEN-TCP-UNEXPECTED",
                    "Unexpected listening TCP port",
                    70,
                    "Process is listening on a TCP port that is not in the configured allowlist.",
                    "Confirm whether this service is expected. If not, stop the process and preserve the log for investigation.",
                    endpoint));
            }
        }

        private void AnalyzeUdpSocket(NetworkEndpoint endpoint, List<Alert> alerts)
        {
            string udpKey = "udp-socket|" + endpoint.LocalAddress + "|" + endpoint.LocalPort + "|" + endpoint.ProcessName;
            if (!state.MarkListenerSeen(udpKey)) return;

            bool trustedUdpProcess = config.TrustedProcesses.Contains(endpoint.ProcessName);
            bool dynamicTrustedSocket = trustedUdpProcess && endpoint.LocalPort >= 49152;
            if (!config.AllowedListeningPorts.Contains(endpoint.LocalPort) && !dynamicTrustedSocket)
            {
                alerts.Add(Alert.FromEndpoint(
                    "NET-LISTEN-UDP-UNEXPECTED",
                    "Unexpected UDP socket",
                    50,
                    "Process has a UDP socket that is not in the configured allowlist.",
                    "Validate whether this local UDP listener is required. Unexpected UDP sockets are common in discovery, tunneling, and local service abuse.",
                    endpoint));
            }
        }

        private void AnalyzeTcpConnection(
            NetworkEndpoint endpoint,
            HashSet<int> tcpListeningPorts,
            Dictionary<string, int> externalConnectionCounts,
            DateTime timestampUtc,
            List<Alert> alerts)
        {
            bool blockedRemote = config.IsBlockedRemote(endpoint.RemoteAddress);
            bool allowedRemote = config.IsAllowedRemote(endpoint.RemoteAddress);
            bool remoteExternal = IpRules.IsExternal(endpoint.RemoteAddress) && !allowedRemote;
            bool remotePrivate = IpRules.IsPrivateNetwork(endpoint.RemoteAddress);
            bool trustedProcess = config.TrustedProcesses.Contains(endpoint.ProcessName);
            bool ordinaryOutboundPort = config.AllowedOutboundPorts.Contains(endpoint.RemotePort);
            bool riskyRemotePort = config.HighRiskRemotePorts.Contains(endpoint.RemotePort);
            bool inboundToLocalListener = remoteExternal && tcpListeningPorts.Contains(endpoint.LocalPort);

            if (remoteExternal || blockedRemote)
            {
                string processKey = endpoint.ProcessName + "|" + endpoint.ProcessId.ToString(CultureInfo.InvariantCulture);
                Increment(externalConnectionCounts, processKey);
            }

            string connectionKey = endpoint.ConnectionKey;
            bool newConnection = state.MarkConnectionSeen(connectionKey);
            if (!newConnection)
            {
                return;
            }

            if (blockedRemote)
            {
                alerts.Add(Alert.FromEndpoint(
                    "NET-IOC-REMOTE-MATCH",
                    "Connection to blocked remote indicator",
                    95,
                    "Remote IP matched the configured blocked indicator list.",
                    "Disconnect the host from untrusted networks, preserve process details, and investigate the process tree.",
                        endpoint));
            }

            if (endpoint.Process != null && config.IsBlockedHash(endpoint.Process.Sha256))
            {
                alerts.Add(Alert.FromEndpoint(
                    "PROC-IOC-HASH-CONNECTION",
                    "Blocked process hash made network connection",
                    95,
                    "Process executable SHA256 matched the configured blocked hash list and has network activity.",
                    "Isolate the host if this hash is malicious. Preserve the executable and process details.",
                    endpoint));
            }

            if (remoteExternal)
            {
                AnalyzeExternalTcpConnection(endpoint, inboundToLocalListener, trustedProcess, ordinaryOutboundPort, riskyRemotePort, timestampUtc, alerts);
            }
            else if (remotePrivate && config.LateralMovementPorts.Contains(endpoint.RemotePort) && !trustedProcess)
            {
                alerts.Add(Alert.FromEndpoint(
                    "NET-LATERAL-PORT",
                    "Untrusted process connected to lateral movement port",
                    65,
                    "Untrusted process connected to an internal administration or file-sharing port.",
                    "Confirm whether this process should talk to internal services. Check for scanning, credential theft, or lateral movement.",
                    endpoint));
            }
        }

        private void AnalyzeExternalTcpConnection(
            NetworkEndpoint endpoint,
            bool inboundToLocalListener,
            bool trustedProcess,
            bool ordinaryOutboundPort,
            bool riskyRemotePort,
            DateTime timestampUtc,
            List<Alert> alerts)
        {
            AnalyzeRatOrientedExternalConnection(endpoint, trustedProcess, alerts);

            if (config.EnforceAuthorizedDnsResolvers &&
                endpoint.RemotePort == 53 &&
                !config.IsAllowedDnsResolver(endpoint.RemoteAddress))
            {
                alerts.Add(Alert.FromEndpoint(
                    "NET-DNS-UNAUTHORIZED-RESOLVER",
                    "External DNS to unauthorized resolver",
                    80,
                    "Process connected to TCP/53 on a resolver that is not configured as authorized.",
                    "Route DNS through approved resolvers. Check for malware DNS, DNS tunneling, or policy bypass.",
                    endpoint));
            }

            if (inboundToLocalListener)
            {
                alerts.Add(Alert.FromEndpoint(
                    "NET-INBOUND-EXTERNAL",
                    "External inbound connection",
                    80,
                    "External host connected to a local TCP listener.",
                    "Confirm whether this service should be reachable. If not, block inbound access and investigate the listening process.",
                    endpoint));
            }
            else if (riskyRemotePort)
            {
                alerts.Add(Alert.FromEndpoint(
                    "NET-EGRESS-HIGH-RISK-PORT",
                    "Outbound connection to high-risk port",
                    85,
                    "Process connected to a remote port commonly associated with shells, proxies, tunnels, IRC, or C2 infrastructure.",
                    "Investigate the process and destination. Consider blocking this egress path at the firewall.",
                    endpoint));
            }
            else if (!trustedProcess && !ordinaryOutboundPort)
            {
                alerts.Add(Alert.FromEndpoint(
                    "NET-EGRESS-UNUSUAL-PORT",
                    "Unusual external outbound connection",
                    65,
                    "Untrusted process connected externally on a port outside the normal outbound allowlist.",
                    "Validate the process, parent process, and destination. Unexpected egress is a common C2 and exfiltration signal.",
                    endpoint));
            }
            else if (trustedProcess && !ordinaryOutboundPort && endpoint.RemotePort < 49152)
            {
                alerts.Add(Alert.FromEndpoint(
                    "NET-EGRESS-PORT-MISUSE",
                    "Trusted process used unusual destination port",
                    55,
                    "Trusted process connected externally on a nonstandard low destination port.",
                    "Review whether the destination port is expected for this process. Tune the allowlist only after confirming business need.",
                    endpoint));
            }
            else if (!trustedProcess)
            {
                alerts.Add(Alert.FromEndpoint(
                    "NET-EGRESS-NEW-UNTRUSTED",
                    "New external outbound connection",
                    35,
                    "Untrusted process made a new external outbound connection.",
                    "Low severity unless repeated, paired with unusual ports, or tied to suspicious process ancestry.",
                    endpoint));
            }

            AnalyzeBeaconing(endpoint, timestampUtc, alerts);
            AnalyzeBaselineForEndpoint(endpoint, alerts);
        }

        private void AnalyzeRatOrientedExternalConnection(NetworkEndpoint endpoint, bool trustedProcess, List<Alert> alerts)
        {
            ProcessInfo process = endpoint.Process;
            string commandLine = process == null ? "" : process.CommandLine;
            string parentName = process == null ? "" : process.ParentProcessName;
            string executablePath = process == null ? "" : process.ExecutablePath;

            bool knownRmm = config.KnownRmmProcesses.Contains(endpoint.ProcessName);
            bool lolbin = config.LolbinProcesses.Contains(endpoint.ProcessName);
            bool suspiciousCommandLine = FileSystemRules.ContainsAny(commandLine, config.SuspiciousCommandLineTerms);
            EncodedCommandFinding encodedCommand = CommandLineRules.FindEncodedCommand(commandLine, config);
            bool suspiciousParent = config.SuspiciousParentProcesses.Contains(parentName);
            bool userWritablePath = FileSystemRules.IsUserWritablePath(executablePath, config);
            bool unsignedProcess = process != null && process.HasExecutablePath && !process.HasSigner;

            if (knownRmm)
            {
                alerts.Add(Alert.FromEndpoint(
                    "RAT-RMM-TOOL-NETWORK",
                    "Remote management tool made external connection",
                    80,
                    "Process name matches a known remote management or remote access tool.",
                    "Confirm this tool is approved. Unauthorized RMM tools are commonly used for persistence and hands-on access.",
                    endpoint));
            }

            if (encodedCommand.Detected)
            {
                alerts.Add(Alert.FromEndpoint(
                    "RAT-ENCODED-CLI-EGRESS",
                    "Encoded command line process made external connection",
                    92,
                    "Process with encoded or base64-like command line made an external network connection. Reason: " + encodedCommand.Reason + ". DecodedPreview: " + encodedCommand.DecodedPreview,
                    "Treat as high-confidence suspicious staging unless expected. Review decoded content, parent process, and destination.",
                    endpoint));
            }

            if (lolbin && suspiciousCommandLine)
            {
                alerts.Add(Alert.FromEndpoint(
                    "RAT-LOLBIN-SUSPICIOUS-EGRESS",
                    "LOLBin with suspicious command line made external connection",
                    90,
                    "A living-off-the-land binary with suspicious command-line content made an external network connection.",
                    "Review parent process and command line immediately. This can indicate RAT staging or C2 bootstrap activity.",
                    endpoint));
            }
            else if (lolbin)
            {
                alerts.Add(Alert.FromEndpoint(
                    "RAT-LOLBIN-EGRESS",
                    "LOLBin made external connection",
                    70,
                    "A living-off-the-land binary made an external network connection.",
                    "Validate whether this process should have internet access. Many RAT chains use LOLBins for download or C2 setup.",
                    endpoint));
            }

            if (suspiciousParent && !trustedProcess)
            {
                alerts.Add(Alert.FromEndpoint(
                    "RAT-SUSPICIOUS-PARENT-EGRESS",
                    "Suspicious parent process lineage with external connection",
                    75,
                    "A process with a suspicious parent lineage made an external connection.",
                    "Inspect the parent and child command lines for script, macro, archive, or browser-spawned execution.",
                    endpoint));
            }

            if (userWritablePath && unsignedProcess)
            {
                alerts.Add(Alert.FromEndpoint(
                    "RAT-UNSIGNED-USERPATH-EGRESS",
                    "Unsigned executable from user-writable path made external connection",
                    85,
                    "Unsigned process running from a user-writable path made an external connection.",
                    "This is a strong RAT/payload signal. Inspect the file hash, parent process, and persistence locations.",
                    endpoint));
            }

            if (config.IsDohProvider(endpoint.RemoteAddress) && !trustedProcess)
            {
                alerts.Add(Alert.FromEndpoint(
                    "DNS-DOH-UNTRUSTED-PROCESS",
                    "Untrusted process connected to DNS-over-HTTPS provider",
                    75,
                    "Untrusted process connected to a known DoH provider IP range.",
                    "Validate whether this process should bypass local DNS policy. Malware can use DoH to hide C2 lookups.",
                    endpoint));
            }

            if (!trustedProcess && (endpoint.RemotePort == 80 || endpoint.RemotePort == 443) && String.IsNullOrWhiteSpace(endpoint.RemoteHost))
            {
                alerts.Add(Alert.FromEndpoint(
                    "NET-DIRECT-IP-WEB-EGRESS",
                    "Untrusted process made direct-IP web connection",
                    60,
                    "Untrusted process connected externally on HTTP/HTTPS without observed hostname context.",
                    "Correlate with DNS telemetry. Direct IP HTTPS from unusual processes is common in RAT and loader traffic.",
                    endpoint));
            }
        }

        private void AnalyzeBaselineForEndpoint(NetworkEndpoint endpoint, List<Alert> alerts)
        {
            string processDestination = endpoint.ProcessName + "|" + endpoint.RemoteAddress + "|" + endpoint.RemotePort.ToString(CultureInfo.InvariantCulture);
            if (baselineStore.Observe("process-destination", processDestination) && ShouldAlertOnBaselineNovelty())
            {
                alerts.Add(Alert.FromEndpoint(
                    "BASELINE-NEW-PROCESS-DESTINATION",
                    "New process/destination pair",
                    45,
                    "This process connected to a destination not previously observed in the local baseline.",
                    "Low severity by itself. Correlate with process lineage, destination reputation, and command-line context.",
                    endpoint));
            }
        }

        private void AnalyzeBeaconing(NetworkEndpoint endpoint, DateTime timestampUtc, List<Alert> alerts)
        {
            string flowKey = endpoint.ProcessName + "|" + endpoint.RemoteAddress + "|" + endpoint.RemotePort.ToString(CultureInfo.InvariantCulture);
            BeaconResult result = state.BeaconTracker.RecordAndEvaluate(
                flowKey,
                timestampUtc,
                config.BeaconMinimumSamples,
                config.BeaconMaxAverageIntervalSeconds,
                config.BeaconMaxJitterRatio);

            if (!result.Detected)
            {
                return;
            }

            string details = "Repeated external connections show low interval variation. Samples=" +
                result.Samples.ToString(CultureInfo.InvariantCulture) +
                ", average_interval_seconds=" + result.AverageIntervalSeconds.ToString("0.0", CultureInfo.InvariantCulture) +
                ", jitter_ratio=" + result.JitterRatio.ToString("0.000", CultureInfo.InvariantCulture) + ".";

            alerts.Add(Alert.FromEndpoint(
                "NET-C2-BEACON-PATTERN",
                "Potential beaconing activity",
                90,
                details,
                "Investigate for command-and-control behavior. Check the process path, parent process, persistence, and destination reputation.",
                endpoint));
        }

        private void AnalyzeConnectionBursts(Dictionary<string, int> externalConnectionCounts, List<Alert> alerts)
        {
            foreach (KeyValuePair<string, int> item in externalConnectionCounts)
            {
                if (item.Value >= config.ConnectionBurstThreshold)
                {
                    alerts.Add(Alert.Create(
                        "NET-EGRESS-CONNECTION-BURST",
                        "External connection burst",
                        75,
                        item.Key + " opened " + item.Value.ToString(CultureInfo.InvariantCulture) + " external TCP connections in one poll interval.",
                        "Check for scanning, fan-out C2, or attempted exfiltration. If expected, tune the process allowlist or threshold.",
                        "burst|" + item.Key));
                }
            }
        }

        private static void Increment(Dictionary<string, int> counts, string key)
        {
            int value;
            counts.TryGetValue(key, out value);
            counts[key] = value + 1;
        }

        private bool ShouldAlertOnBaselineNovelty()
        {
            return config.BaselineEnabled && !config.BaselineLearningMode && !baselineStore.IsWarmupActive;
        }

        private bool ContainsBlockedHash(string hashes)
        {
            if (String.IsNullOrWhiteSpace(hashes)) return false;
            foreach (string blockedHash in config.BlockedHashes)
            {
                if (blockedHash.Length > 0 && hashes.IndexOf(blockedHash, StringComparison.OrdinalIgnoreCase) >= 0)
                {
                    return true;
                }
            }

            return false;
        }

        private static string NormalizeDomain(string domain)
        {
            return String.IsNullOrWhiteSpace(domain) ? "" : domain.Trim().TrimEnd('.').ToLowerInvariant();
        }
    }
}
