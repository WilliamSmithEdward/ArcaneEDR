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
        private readonly RemoteEndpointEnricher remoteEndpointEnricher;
        private readonly RemoteEndpointPolicyEngine remoteEndpointPolicyEngine;

        public NetworkTrafficAnalyzer(MonitorConfig config, DetectionState state, BaselineStore baselineStore)
            : this(config, state, baselineStore, null, null)
        {
        }

        public NetworkTrafficAnalyzer(MonitorConfig config, DetectionState state, BaselineStore baselineStore, RemoteEndpointEnricher remoteEndpointEnricher)
            : this(config, state, baselineStore, remoteEndpointEnricher, null)
        {
        }

        public NetworkTrafficAnalyzer(
            MonitorConfig config,
            DetectionState state,
            BaselineStore baselineStore,
            RemoteEndpointEnricher remoteEndpointEnricher,
            RemoteEndpointPolicyEngine remoteEndpointPolicyEngine)
        {
            this.config = config;
            this.state = state;
            this.baselineStore = baselineStore;
            this.remoteEndpointEnricher = remoteEndpointEnricher;
            this.remoteEndpointPolicyEngine = remoteEndpointPolicyEngine;
        }

        public List<Alert> Analyze(NetworkSnapshot snapshot, DateTime timestampUtc)
        {
            List<Alert> alerts = new List<Alert>();
            Dictionary<string, int> externalConnectionCounts = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
            HashSet<int> externallyReachableTcpListeningPorts = GetExternallyReachableTcpListeningPorts(snapshot);

            if (remoteEndpointEnricher != null)
            {
                remoteEndpointEnricher.Enrich(snapshot);
            }

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

                AnalyzeTcpConnection(endpoint, externallyReachableTcpListeningPorts, externalConnectionCounts, timestampUtc, alerts);
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

        private static HashSet<int> GetExternallyReachableTcpListeningPorts(NetworkSnapshot snapshot)
        {
            HashSet<int> ports = new HashSet<int>();
            foreach (NetworkEndpoint endpoint in snapshot.Endpoints)
            {
                if (endpoint.IsTcpListener && IsExternallyReachableListener(endpoint))
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
                if (IsLoopbackOnlyListener(endpoint))
                {
                    alerts.Add(Alert.FromEndpoint(
                        "NET-LISTEN-TCP-LOCALHOST-UNEXPECTED",
                        "Unexpected localhost-only TCP listener",
                        35,
                        "Process is listening on a loopback-only TCP port that is not in the configured allowlist.",
                        "Confirm whether this local-only listener is expected. It is less exposed than a wildcard or LAN-bound listener, but can still matter when paired with suspicious process activity.",
                        endpoint));
                }
                else
                {
                    alerts.Add(Alert.FromEndpoint(
                        "NET-LISTEN-TCP-UNEXPECTED",
                        "Unexpected reachable TCP listener",
                        70,
                        "Process is listening on a TCP port that is not in the configured allowlist and is not loopback-only.",
                        "Confirm whether this service is expected. If not, stop the process and preserve the log for investigation.",
                        endpoint));
                }
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
                if (IsLoopbackOnlyListener(endpoint))
                {
                    alerts.Add(Alert.FromEndpoint(
                        "NET-LISTEN-UDP-LOCALHOST-UNEXPECTED",
                        "Unexpected localhost-only UDP socket",
                        30,
                        "Process has a loopback-only UDP socket that is not in the configured allowlist.",
                        "Validate whether this local-only UDP socket is required. Treat it as higher priority if paired with suspicious process, DNS, or persistence alerts.",
                        endpoint));
                }
                else
                {
                    alerts.Add(Alert.FromEndpoint(
                        "NET-LISTEN-UDP-UNEXPECTED",
                        "Unexpected UDP socket",
                        50,
                        "Process has a UDP socket that is not in the configured allowlist and is not loopback-only.",
                        "Validate whether this local UDP listener is required. Unexpected UDP sockets are common in discovery, tunneling, and local service abuse.",
                        endpoint));
                }
            }
        }

        private void AnalyzeTcpConnection(
            NetworkEndpoint endpoint,
            HashSet<int> tcpListeningPorts,
            Dictionary<string, int> externalConnectionCounts,
            DateTime timestampUtc,
            List<Alert> alerts)
        {
            RemoteEndpointPolicyDecision remotePolicy = EvaluateRemotePolicy(endpoint);
            bool remoteExternal = IpRules.IsExternal(endpoint.RemoteAddress) &&
                (!remotePolicy.IsAllow || remotePolicy.IsHighSignal || remotePolicy.IsTrust);
            bool remotePrivate = IpRules.IsPrivateNetwork(endpoint.RemoteAddress);
            bool trustedProcess = config.TrustedProcesses.Contains(endpoint.ProcessName);
            bool ordinaryOutboundPort = IsAllowedOutboundPort(endpoint);
            bool riskyRemotePort = config.HighRiskRemotePorts.Contains(endpoint.RemotePort);
            bool inboundToLocalListener = tcpListeningPorts.Contains(endpoint.LocalPort);

            if (remoteExternal || remotePolicy.IsHighSignal)
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

            bool firstSeenProcessRemoteIp = ObserveProcessRemoteIp(endpoint);
            int endpointAlertStart = alerts.Count;

            if (remotePolicy.IsHighSignal)
            {
                alerts.Add(RemoteEndpointPolicyAlert(endpoint, remotePolicy));
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
                AnalyzeExternalTcpConnection(endpoint, inboundToLocalListener, trustedProcess, ordinaryOutboundPort, riskyRemotePort, remotePolicy, timestampUtc, alerts);
            }
            else if (remotePrivate)
            {
                AnalyzePrivateTcpConnection(endpoint, inboundToLocalListener, trustedProcess, alerts);
            }

            ApplyObservedRemotePolicy(endpoint, remotePolicy, firstSeenProcessRemoteIp, alerts, endpointAlertStart);
        }

        private void AnalyzePrivateTcpConnection(
            NetworkEndpoint endpoint,
            bool inboundToLocalListener,
            bool trustedProcess,
            List<Alert> alerts)
        {
            if (inboundToLocalListener && config.LateralMovementPorts.Contains(endpoint.LocalPort))
            {
                alerts.Add(Alert.FromEndpoint(
                    "NET-LAN-INBOUND-LATERAL-PORT",
                    "LAN host connected to local administration port",
                    70,
                    "A private-network host connected to a local listener on an administration, file-sharing, remote-management, or lateral-movement port.",
                    "Confirm whether this LAN access is expected. Unauthorized inbound access to these ports can indicate hands-on activity or lateral movement.",
                    endpoint));
                return;
            }

            if (!inboundToLocalListener &&
                config.LateralMovementPorts.Contains(endpoint.RemotePort) &&
                !trustedProcess)
            {
                alerts.Add(Alert.FromEndpoint(
                    "NET-LAN-EGRESS-LATERAL-PORT",
                    "Untrusted process connected to LAN administration port",
                    65,
                    "Untrusted process connected to a private-network administration, file-sharing, remote-management, or lateral-movement port.",
                    "Confirm whether this process should talk to internal services. Check for scanning, credential theft, remote access, or lateral movement.",
                    endpoint));
            }
        }

        private void AnalyzeExternalTcpConnection(
            NetworkEndpoint endpoint,
            bool inboundToLocalListener,
            bool trustedProcess,
            bool ordinaryOutboundPort,
            bool riskyRemotePort,
            RemoteEndpointPolicyDecision remotePolicy,
            DateTime timestampUtc,
            List<Alert> alerts)
        {
            int endpointSpecificAlertStart = alerts.Count;
            AnalyzeRatOrientedExternalConnection(endpoint, trustedProcess, remotePolicy, alerts);
            bool endpointSpecificAlertEmitted = alerts.Count > endpointSpecificAlertStart;

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
                bool trustedAlternateWebPort = trustedProcess &&
                    IsCommonAlternateWebPort(endpoint.RemotePort) &&
                    IsSignedNonUserWritableProcess(endpoint);

                alerts.Add(Alert.FromEndpoint(
                    trustedAlternateWebPort ? "NET-EGRESS-TRUSTED-ALT-WEB-PORT" : "NET-EGRESS-HIGH-RISK-PORT",
                    trustedAlternateWebPort ? "Trusted process used alternate web/proxy port" : "Outbound connection to high-risk port",
                    trustedAlternateWebPort ? 55 : 85,
                    trustedAlternateWebPort
                        ? "Trusted signed process connected externally on a common alternate web/proxy port that is also in the high-risk remote-port list."
                        : "Process connected to a remote port commonly associated with shells, proxies, tunnels, IRC, or C2 infrastructure.",
                    trustedAlternateWebPort
                        ? "Keep as local context unless paired with suspicious process lineage, direct execution, persistence, PowerShell staging, or threat intelligence."
                        : "Investigate the process and destination. Consider blocking this egress path at the firewall.",
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
            else if (!trustedProcess && !endpointSpecificAlertEmitted)
            {
                alerts.Add(Alert.FromEndpoint(
                    "NET-EGRESS-NEW-UNTRUSTED",
                    "New external outbound connection",
                    35,
                    "Untrusted process made a new external outbound connection.",
                    "Low severity unless repeated, paired with unusual ports, or tied to suspicious process ancestry.",
                    endpoint));
            }

            AnalyzeBeaconing(endpoint, timestampUtc, remotePolicy, alerts);
            AnalyzeBaselineForEndpoint(endpoint, alerts);
        }

        private void AnalyzeRatOrientedExternalConnection(NetworkEndpoint endpoint, bool trustedProcess, RemoteEndpointPolicyDecision remotePolicy, List<Alert> alerts)
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

            if (!trustedProcess && IsOrdinaryWebPort(endpoint) && String.IsNullOrWhiteSpace(endpoint.RemoteHost))
            {
                bool lowRiskSignedProcess = IsSignedNonUserWritableProcess(endpoint) &&
                    !HasStrongSuspiciousEndpointContext(endpoint, trustedProcess, false, remotePolicy);
                bool trustedRemoteContext = remotePolicy.IsTrust &&
                    IsExpectedRemoteContextProcess(endpoint, trustedProcess) &&
                    !HasStrongSuspiciousEndpointContext(endpoint, trustedProcess, false, remotePolicy);
                bool lowerRiskContext = lowRiskSignedProcess || trustedRemoteContext;

                alerts.Add(Alert.FromEndpoint(
                    lowerRiskContext ? "NET-DIRECT-IP-WEB-EGRESS-SIGNED" : "NET-DIRECT-IP-WEB-EGRESS",
                    lowerRiskContext ? "Lower-risk direct-IP web connection" : "Untrusted process made direct-IP web connection",
                    trustedRemoteContext ? 35 : (lowRiskSignedProcess ? 45 : 60),
                    lowerRiskContext
                        ? "Process connected externally on HTTP/HTTPS without observed hostname context, but local process and remote enrichment context are lower risk. " + RemoteContextSentence(endpoint)
                        : "Untrusted process connected externally on HTTP/HTTPS without observed hostname context.",
                    lowerRiskContext
                        ? "Keep as local context unless it repeats with suspicious process lineage, persistence, PowerShell staging, risky ports, or threat intelligence."
                        : "Correlate with DNS telemetry. Direct IP HTTPS from unusual processes is common in RAT and loader traffic.",
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

        private bool ObserveProcessRemoteIp(NetworkEndpoint endpoint)
        {
            if (baselineStore == null || endpoint == null || endpoint.RemoteAddress == null) return false;

            string processRemoteIp = endpoint.ProcessName + "|" + endpoint.RemoteAddress;
            return baselineStore.Observe("process-remote-ip", processRemoteIp);
        }

        private void ApplyObservedRemotePolicy(
            NetworkEndpoint endpoint,
            RemoteEndpointPolicyDecision remotePolicy,
            bool firstSeenProcessRemoteIp,
            List<Alert> alerts,
            int endpointAlertStart)
        {
            if (remotePolicy == null || !remotePolicy.IsObserve || !remotePolicy.Matched || remotePolicy.Score <= 0)
            {
                return;
            }

            List<string> pairedContext = ObservedRemotePolicyPairingContext(alerts, endpointAlertStart);
            if (firstSeenProcessRemoteIp)
            {
                pairedContext.Insert(0, "first-seen app/remote-IP pair");
            }

            if (pairedContext.Count > 0)
            {
                alerts.Add(ObservedRemotePolicyCriticalAlert(endpoint, remotePolicy, pairedContext));
                return;
            }

            for (int index = endpointAlertStart; index < alerts.Count; index++)
            {
                ApplyObservedRemotePolicyScore(alerts[index], remotePolicy);
            }
        }

        private static List<string> ObservedRemotePolicyPairingContext(List<Alert> alerts, int endpointAlertStart)
        {
            List<string> result = new List<string>();
            if (alerts == null) return result;

            for (int index = Math.Max(0, endpointAlertStart); index < alerts.Count; index++)
            {
                Alert alert = alerts[index];
                if (!IsStrongObservedPolicyPair(alert)) continue;

                string ruleId = alert.RuleId ?? "";
                if (!ContainsText(result, ruleId)) result.Add(ruleId);
            }

            return result;
        }

        private static bool IsStrongObservedPolicyPair(Alert alert)
        {
            if (alert == null) return false;
            string ruleId = alert.RuleId ?? "";
            if (AlertRuleTaxonomy.HasPrefix(ruleId, AlertRuleTaxonomy.PrefixRat)) return true;
            if (AlertRuleTaxonomy.IsDnsRule(ruleId)) return true;
            return alert.Score >= 75;
        }

        private static bool ContainsText(List<string> values, string expected)
        {
            if (values == null || String.IsNullOrWhiteSpace(expected)) return false;
            foreach (string value in values)
            {
                if (expected.Equals(value, StringComparison.OrdinalIgnoreCase)) return true;
            }

            return false;
        }

        private static void ApplyObservedRemotePolicyScore(Alert alert, RemoteEndpointPolicyDecision remotePolicy)
        {
            if (alert == null || remotePolicy == null || remotePolicy.Score <= 0) return;

            int boostedScore = alert.Score + remotePolicy.Score;
            if (boostedScore > 89) boostedScore = 89;
            if (boostedScore > alert.Score)
            {
                alert.SetScore(boostedScore);
            }

            string policyContext = "remote_endpoint_policy=" + SafePolicyToken(remotePolicy.RuleId) + ":" + SafePolicyToken(remotePolicy.Action);
            alert.AddPolicyContext(policyContext);
            alert.AddWhy("Observed remote endpoint policy added review weight: " + Compact(remotePolicy.Reason, 140) + ".");
        }

        private void AnalyzeBeaconing(NetworkEndpoint endpoint, DateTime timestampUtc, RemoteEndpointPolicyDecision remotePolicy, List<Alert> alerts)
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

            bool trustedProcess = config.TrustedProcesses.Contains(endpoint.ProcessName);
            bool riskyRemotePort = config.HighRiskRemotePorts.Contains(endpoint.RemotePort);
            bool trustedRemoteContext = remotePolicy.IsTrust;
            bool lowRiskTimingOnly = IsExpectedSignedNormalWebEndpoint(endpoint, trustedProcess) &&
                !HasStrongSuspiciousEndpointContext(endpoint, trustedProcess, riskyRemotePort, remotePolicy);
            if (!lowRiskTimingOnly &&
                trustedRemoteContext &&
                IsExpectedRemoteContextProcess(endpoint, trustedProcess) &&
                !HasStrongSuspiciousEndpointContext(endpoint, trustedProcess, riskyRemotePort, remotePolicy))
            {
                lowRiskTimingOnly = true;
            }

            alerts.Add(Alert.FromEndpoint(
                lowRiskTimingOnly ? "NET-BEACON-TIMING-LOW-RISK" : "NET-C2-BEACON-PATTERN",
                lowRiskTimingOnly ? "Beacon-like timing from low-risk process" : "Potential beaconing activity",
                lowRiskTimingOnly ? 55 : 90,
                lowRiskTimingOnly
                    ? details + " The process and remote enrichment context are expected, using a normal web port, and no paired high-risk context was observed. " + RemoteContextSentence(endpoint)
                    : details,
                lowRiskTimingOnly
                    ? "Keep as local context. Escalate if paired with unsigned/user-writable execution, persistence, PowerShell staging, unusual ports, suspicious parentage, or threat intelligence."
                    : "Investigate for command-and-control behavior. Check the process path, parent process, persistence, and destination reputation.",
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

        private static bool IsLoopbackOnlyListener(NetworkEndpoint endpoint)
        {
            return endpoint != null &&
                endpoint.LocalAddress != null &&
                IPAddress.IsLoopback(endpoint.LocalAddress);
        }

        private static bool IsExternallyReachableListener(NetworkEndpoint endpoint)
        {
            return endpoint != null &&
                endpoint.IsTcpListener &&
                !IsLoopbackOnlyListener(endpoint);
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

        private RemoteEndpointPolicyDecision EvaluateRemotePolicy(NetworkEndpoint endpoint)
        {
            return remoteEndpointPolicyEngine == null
                ? RemoteEndpointPolicyDecision.None
                : remoteEndpointPolicyEngine.Evaluate(endpoint);
        }

        private static Alert RemoteEndpointPolicyAlert(NetworkEndpoint endpoint, RemoteEndpointPolicyDecision decision)
        {
            string ruleId = decision.IsBlock
                ? AlertRuleTaxonomy.RuleNetworkRemotePolicyBlocked
                : AlertRuleTaxonomy.RuleNetworkRemotePolicyCritical;
            string action = decision.Action ?? "";
            string policyContext = "remote_endpoint_policy=" + SafePolicyToken(decision.RuleId) + ":" + SafePolicyToken(action);
            string body = "Ordered remote endpoint policy matched id=" + SafePolicyToken(decision.RuleId) +
                " action=" + SafePolicyToken(action) +
                " reason=" + Compact(decision.Reason, 180) + ". " +
                RemoteContextSentence(endpoint);
            string recommendation = decision.IsBlock
                ? "Review the process, parent, command line, and destination immediately. If this destination is expected, add a narrower rule above this policy entry."
                : "Treat this as critical review context. If the destination is expected, add a narrower allow or trust rule above this policy entry.";
            Alert alert = Alert.FromEndpoint(
                ruleId,
                decision.IsBlock ? "Connection matched blocked remote endpoint policy" : "Connection matched critical remote endpoint policy",
                decision.Score,
                body,
                recommendation,
                endpoint);
            alert.CooldownKey = ruleId + "|" +
                SafePolicyToken(decision.RuleId) + "|" +
                SafePolicyToken(endpoint.ProcessName) + "|" +
                (endpoint.RemoteAddress == null ? "" : endpoint.RemoteAddress.ToString()) + "|" +
                endpoint.RemotePort.ToString(CultureInfo.InvariantCulture);
            alert.AddPolicyContext(policyContext);
            alert.EntitySummary = AppendEntity(alert.EntitySummary, "policy=" + policyContext);
            return alert;
        }

        private static Alert ObservedRemotePolicyCriticalAlert(
            NetworkEndpoint endpoint,
            RemoteEndpointPolicyDecision decision,
            List<string> pairedContext)
        {
            string action = decision.Action ?? "";
            string policyContext = "remote_endpoint_policy=" + SafePolicyToken(decision.RuleId) + ":" + SafePolicyToken(action);
            string paired = JoinContext(pairedContext);
            string body = "Observed remote endpoint policy matched id=" + SafePolicyToken(decision.RuleId) +
                " action=" + SafePolicyToken(action) +
                " reason=" + Compact(decision.Reason, 180) + ". " +
                "Escalated because it was paired with: " + paired + ". " +
                RemoteContextSentence(endpoint);
            Alert alert = Alert.FromEndpoint(
                AlertRuleTaxonomy.RuleNetworkRemotePolicyCritical,
                "Observed remote endpoint context escalated by paired signal",
                90,
                body,
                "Review the process, parent, command line, and destination. If this destination is expected, add a narrower trust or observe rule above this policy entry.",
                endpoint);
            alert.CooldownKey = AlertRuleTaxonomy.RuleNetworkRemotePolicyCritical + "|observed|" +
                SafePolicyToken(decision.RuleId) + "|" +
                SafePolicyToken(endpoint.ProcessName) + "|" +
                (endpoint.RemoteAddress == null ? "" : endpoint.RemoteAddress.ToString()) + "|" +
                endpoint.RemotePort.ToString(CultureInfo.InvariantCulture);
            alert.AddPolicyContext(policyContext);
            alert.AddWhy("Observed remote endpoint policy became critical because it was paired with: " + paired + ".");
            alert.EntitySummary = AppendEntity(alert.EntitySummary, "policy=" + policyContext);
            return alert;
        }

        private bool HasStrongSuspiciousEndpointContext(NetworkEndpoint endpoint, bool trustedProcess, bool riskyRemotePort, RemoteEndpointPolicyDecision remotePolicy)
        {
            if (endpoint == null) return false;
            if (remotePolicy != null && remotePolicy.IsHighSignal) return true;
            if (riskyRemotePort) return true;
            if (config.IsDynamicDnsDomain(endpoint.RemoteHost)) return true;
            if (config.IsDohProvider(endpoint.RemoteAddress) && !trustedProcess) return true;

            ProcessInfo process = endpoint.Process;
            if (process == null) return !trustedProcess;

            string commandLine = process.CommandLine ?? "";
            string parentName = process.ParentProcessName ?? "";
            string executablePath = process.ExecutablePath ?? "";

            if (config.IsBlockedHash(process.Sha256)) return true;
            if (config.KnownRmmProcesses.Contains(endpoint.ProcessName)) return true;
            if (config.LolbinProcesses.Contains(endpoint.ProcessName)) return true;
            if (FileSystemRules.ContainsAny(commandLine, config.SuspiciousCommandLineTerms)) return true;
            if (CommandLineRules.FindEncodedCommand(commandLine, config).Detected) return true;
            if (config.SuspiciousParentProcesses.Contains(parentName) && !trustedProcess) return true;
            if (FileSystemRules.IsUserWritablePath(executablePath, config)) return true;

            return false;
        }

        private bool IsExpectedSignedNormalWebEndpoint(NetworkEndpoint endpoint, bool trustedProcess)
        {
            return endpoint != null &&
                IsOrdinaryWebPort(endpoint) &&
                IsSignedNonUserWritableProcess(endpoint) &&
                (trustedProcess || IsAgentProfileEndpoint(endpoint));
        }

        private bool IsAgentProfileEndpoint(NetworkEndpoint endpoint)
        {
            if (endpoint == null || !config.EnableAgentProfile) return false;

            ProcessInfo process = endpoint.Process;
            string processName = endpoint.ProcessName ?? "";
            string parentName = process == null ? "" : (process.ParentProcessName ?? "");

            return config.AgentProcessNames.Contains(processName) ||
                config.AgentProcessNames.Contains(parentName) ||
                config.AgentChildProcessNames.Contains(processName) ||
                config.AgentPackageManagerProcesses.Contains(processName);
        }

        private bool IsExpectedRemoteContextProcess(NetworkEndpoint endpoint, bool trustedProcess)
        {
            return endpoint != null &&
                IsOrdinaryWebPort(endpoint) &&
                (trustedProcess || IsAgentProfileEndpoint(endpoint));
        }

        private static string RemoteContextSentence(NetworkEndpoint endpoint)
        {
            if (endpoint == null) return "Remote context was unavailable.";

            string summary = endpoint.RemoteContextSummary();
            return String.IsNullOrWhiteSpace(summary)
                ? "Remote context was unavailable."
                : "Remote context: " + summary + ".";
        }

        private static string SafePolicyToken(string value)
        {
            if (String.IsNullOrWhiteSpace(value)) return "unknown";
            return value.Trim()
                .Replace(" ", "_")
                .Replace(",", "_")
                .Replace(";", "_")
                .Replace("|", "_")
                .Replace("\r", "")
                .Replace("\n", "");
        }

        private static string AppendEntity(string value, string addition)
        {
            if (String.IsNullOrWhiteSpace(value)) return addition;
            return value + " " + addition;
        }

        private static string JoinContext(List<string> values)
        {
            if (values == null || values.Count == 0) return "unspecified paired context";
            return String.Join(", ", values.ToArray());
        }

        private static string Compact(string value, int maxLength)
        {
            if (String.IsNullOrWhiteSpace(value)) return "not specified";
            string compact = value.Replace("\r", " ").Replace("\n", " ").Trim();
            if (compact.Length <= maxLength) return compact;
            return compact.Substring(0, Math.Max(0, maxLength - 3)) + "...";
        }

        private bool IsAllowedOutboundPort(NetworkEndpoint endpoint)
        {
            if (endpoint == null) return false;
            if (config.AllowedOutboundPorts.Contains(endpoint.RemotePort)) return true;

            PortRuleSet processPorts;
            if (!String.IsNullOrWhiteSpace(endpoint.ProcessName) &&
                config.ProcessAllowedOutboundPorts.TryGetValue(endpoint.ProcessName, out processPorts) &&
                processPorts.Contains(endpoint.RemotePort))
            {
                return true;
            }

            return false;
        }

        private bool IsSignedNonUserWritableProcess(NetworkEndpoint endpoint)
        {
            ProcessInfo process = endpoint == null ? null : endpoint.Process;
            if (process == null || !process.HasSigner || !process.HasExecutablePath) return false;

            return !FileSystemRules.IsUserWritablePath(process.ExecutablePath, config);
        }

        private static bool IsOrdinaryWebPort(NetworkEndpoint endpoint)
        {
            return endpoint != null && (endpoint.RemotePort == 80 || endpoint.RemotePort == 443);
        }

        private static bool IsCommonAlternateWebPort(int port)
        {
            return port == 8080 || port == 8443;
        }

        private static string NormalizeDomain(string domain)
        {
            return String.IsNullOrWhiteSpace(domain) ? "" : domain.Trim().TrimEnd('.').ToLowerInvariant();
        }
    }
}
