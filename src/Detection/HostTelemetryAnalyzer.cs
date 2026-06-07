using System;
using System.Collections.Generic;
using System.Globalization;

namespace ArcaneEDR
{
    internal sealed class HostTelemetryAnalyzer
    {
        private readonly MonitorConfig config;
        private readonly DetectionState state;
        private readonly ReputationCache reputationCache;
        private readonly CustomRuleEngine customRuleEngine;
        private readonly Dictionary<string, List<DateTime>> failedLogonsByRemote = new Dictionary<string, List<DateTime>>(StringComparer.OrdinalIgnoreCase);

        public HostTelemetryAnalyzer(
            MonitorConfig config,
            DetectionState state,
            ReputationCache reputationCache,
            CustomRuleEngine customRuleEngine)
        {
            this.config = config;
            this.state = state;
            this.reputationCache = reputationCache;
            this.customRuleEngine = customRuleEngine;
        }

        public List<Alert> Analyze(NetworkSnapshot snapshot, DateTime timestampUtc)
        {
            List<Alert> alerts = new List<Alert>();

            AnalyzePowerShell(snapshot.HostTelemetry.PowerShellEvents, alerts);
            AnalyzeWindowsEvents(snapshot.HostTelemetry.WindowsEvents, timestampUtc, alerts);
            AnalyzePersistence(snapshot.HostTelemetry.PersistenceItems, alerts);
            AnalyzeProcessReputation(snapshot.ProcessEvents, alerts);
            AnalyzeCustomNetworkRules(snapshot.Endpoints, alerts);

            return alerts;
        }

        private void AnalyzePowerShell(List<PowerShellEvent> events, List<Alert> alerts)
        {
            foreach (PowerShellEvent ev in events)
            {
                if (!state.MarkEventSeen("powershell|" + ev.CooldownKey)) continue;

                string text = ev.SearchText;
                EncodedCommandFinding encoded = CommandLineRules.FindEncodedCommand(text, config);
                bool suspiciousTerm = FileSystemRules.ContainsAny(text, config.SuspiciousCommandLineTerms);
                bool downloadCradle = ContainsAny(text, "downloadstring", "downloadfile", "invoke-webrequest", " iwr ", "curl ", "wget ", "bitsadmin", "certutil", "http://", "https://");
                bool defenderTamper = ContainsAny(text, "set-mppreference", "disableantispyware", "disablerealtimemonitoring", "add-mppreference", "exclusionpath", "exclusionprocess");
                bool stealth = ContainsAny(text, "-windowstyle hidden", "-w hidden", "-nop", "-noprofile", "executionpolicy bypass", "-ep bypass");
                bool persistence = ContainsAny(text, "new-service", "sc.exe create", "schtasks", "\\currentversion\\run", "startup");

                if (encoded.Detected)
                {
                    alerts.Add(Alert.FromPowerShellEvent(
                        "PS-ENCODED-COMMAND",
                        "PowerShell encoded or obfuscated command detected",
                        92,
                        "PowerShell telemetry includes encoded/base64-like content. Reason: " + encoded.Reason + ". DecodedPreview: " + encoded.DecodedPreview,
                        "Review the decoded payload and parent process. Encoded PowerShell is common in loader and RAT staging activity.",
                        ev));
                }

                if (defenderTamper)
                {
                    alerts.Add(Alert.FromPowerShellEvent(
                        "PS-DEFENDER-TAMPER",
                        "PowerShell attempted security-control tampering",
                        90,
                        "PowerShell command text includes Microsoft Defender disablement or exclusion terms.",
                        "Confirm whether this was an authorized administrative action. If not, isolate the host and review process lineage.",
                        ev));
                }

                if (downloadCradle && stealth)
                {
                    alerts.Add(Alert.FromPowerShellEvent(
                        "PS-STEALTH-DOWNLOAD-CRADLE",
                        "Stealthy PowerShell download cradle",
                        88,
                        "PowerShell command text combines network download behavior with hidden/no-profile/bypass execution flags.",
                        "Treat as suspicious staging unless explicitly expected. Inspect downloaded content and subsequent process creation.",
                        ev));
                }
                else if (downloadCradle || suspiciousTerm)
                {
                    alerts.Add(Alert.FromPowerShellEvent(
                        "PS-SUSPICIOUS-COMMAND",
                        "Suspicious PowerShell command",
                        75,
                        "PowerShell command text contains terms associated with downloads, encoded execution, or script staging.",
                        "Validate the script source and user intent. Tune terms only after confirming a stable administrative workflow.",
                        ev));
                }

                if (persistence)
                {
                    alerts.Add(Alert.FromPowerShellEvent(
                        "PS-PERSISTENCE-COMMAND",
                        "PowerShell persistence command",
                        82,
                        "PowerShell command text references service, scheduled-task, Run-key, or Startup-folder persistence.",
                        "Review the created persistence item and originating process. Unauthorized persistence is a common RAT behavior.",
                        ev));
                }

                alerts.AddRange(customRuleEngine.AnalyzePowerShell(ev));
            }
        }

        private void AnalyzeWindowsEvents(List<WindowsAuditEvent> events, DateTime timestampUtc, List<Alert> alerts)
        {
            foreach (WindowsAuditEvent ev in events)
            {
                if (!state.MarkEventSeen("windows|" + ev.CooldownKey)) continue;

                if (ev.EventId == 4625)
                {
                    AnalyzeFailedLogon(ev, timestampUtc, alerts);
                }
                else if (ev.EventId == 4624)
                {
                    AnalyzeSuccessfulLogon(ev, alerts);
                }
                else if (ev.EventId == 4672)
                {
                    alerts.Add(Alert.FromWindowsEvent(
                        "AUTH-SPECIAL-PRIVILEGES",
                        "Privileged logon observed",
                        50,
                        "Windows reported special privileges assigned to a logon session.",
                        "Correlate with user, source, and time of day. This is low severity unless paired with remote logon or process staging.",
                        ev));
                }
                else if (ev.EventId == 4697 || ev.EventId == 7045)
                {
                    AnalyzeServiceInstall(ev, alerts);
                }
                else if (ev.EventId == 4698 || ev.EventId == 4702)
                {
                    AnalyzeScheduledTaskEvent(ev, alerts);
                }
                else if (ev.EventId == 4688)
                {
                    AnalyzeAuditProcessCreation(ev, alerts);
                }

                alerts.AddRange(customRuleEngine.AnalyzeWindowsEvent(ev));
            }
        }

        private void AnalyzeFailedLogon(WindowsAuditEvent ev, DateTime timestampUtc, List<Alert> alerts)
        {
            if (IsRemoteAddress(ev.IpAddress))
            {
                RecordFailedLogon(ev.IpAddress, timestampUtc);
                int count = CountRecentFailedLogons(ev.IpAddress, timestampUtc);
                if (count >= 5)
                {
                    alerts.Add(Alert.FromWindowsEvent(
                        "AUTH-FAILED-LOGON-BURST",
                        "Repeated failed remote logons",
                        80,
                        "At least " + count.ToString(CultureInfo.InvariantCulture) + " failed logons from the same remote source were observed in the recent window.",
                        "Check for password spraying, exposed services, or compromised credentials. Consider blocking the source if unexpected.",
                        ev));
                }
                else
                {
                    alerts.Add(Alert.FromWindowsEvent(
                        "AUTH-FAILED-REMOTE-LOGON",
                        "Failed remote logon",
                        60,
                        "A failed Windows logon came from a remote source.",
                        "Review the source and account. Single failures can be benign; repeated failures indicate brute force or password spray.",
                        ev));
                }
            }
        }

        private void AnalyzeSuccessfulLogon(WindowsAuditEvent ev, List<Alert> alerts)
        {
            if (!IsRemoteAddress(ev.IpAddress)) return;

            if (ev.LogonType == "10")
            {
                alerts.Add(Alert.FromWindowsEvent(
                    "AUTH-RDP-LOGON",
                    "Remote desktop logon observed",
                    80,
                    "A successful RDP-style logon was observed from a remote source.",
                    "Confirm this was expected. Unauthorized RDP access is a direct RAT-like hands-on-access signal.",
                    ev));
            }
            else if (ev.LogonType == "3")
            {
                alerts.Add(Alert.FromWindowsEvent(
                    "AUTH-NETWORK-LOGON",
                    "Remote network logon observed",
                    55,
                    "A successful network logon was observed from a remote source.",
                    "Correlate with SMB/admin activity and the target account. Tune only after confirming normal management workflows.",
                    ev));
            }
        }

        private void AnalyzeServiceInstall(WindowsAuditEvent ev, List<Alert> alerts)
        {
            string text = ev.SearchText;
            bool suspicious = IsSuspiciousCommandText(text) || IsUserWritableText(text) || IsKnownRmmText(text);
            bool trusted = !suspicious && IsTrustedPersistenceText(ev.ServiceName, ev.ProcessName, ev.CommandLine);

            alerts.Add(Alert.FromWindowsEvent(
                suspicious ? "PERSIST-SERVICE-INSTALL-SUSPICIOUS" : (trusted ? "PERSIST-SERVICE-INSTALL-TRUSTED" : "PERSIST-SERVICE-INSTALL"),
                suspicious ? "Suspicious service installation" : (trusted ? "Trusted-location service installation observed" : "Service installation observed"),
                suspicious ? 90 : (trusted ? 50 : 78),
                suspicious
                    ? "A new service was installed with command/path traits associated with RAT persistence or remote management tooling."
                    : (trusted
                        ? "A service installation matched configured trusted persistence name/path indicators and did not include suspicious command, user-writable path, or RMM traits."
                        : "A new service installation was observed."),
                "Confirm the service owner, binary path, signer, and install source. Unauthorized services are common persistence mechanisms.",
                ev));
        }

        private void AnalyzeScheduledTaskEvent(WindowsAuditEvent ev, List<Alert> alerts)
        {
            string text = ev.SearchText;
            bool suspicious = IsSuspiciousCommandText(text) || IsUserWritableText(text) || IsKnownRmmText(text);
            bool trusted = !suspicious && IsTrustedPersistenceText(ev.TaskName, ev.ProcessName, ev.CommandLine);

            alerts.Add(Alert.FromWindowsEvent(
                suspicious ? "PERSIST-SCHEDULED-TASK-SUSPICIOUS" : (trusted ? "PERSIST-SCHEDULED-TASK-TRUSTED" : "PERSIST-SCHEDULED-TASK-CHANGE"),
                suspicious ? "Suspicious scheduled task change" : (trusted ? "Trusted-location scheduled task change observed" : "Scheduled task change observed"),
                suspicious ? 85 : (trusted ? 45 : 70),
                suspicious
                    ? "A scheduled task was created or updated with command/path traits associated with staging or RAT persistence."
                    : (trusted
                        ? "A scheduled task change matched configured trusted persistence name/path indicators and did not include suspicious command, user-writable path, or RMM traits."
                        : "A scheduled task was created or updated."),
                "Review task action, author, trigger, and command path. Unauthorized tasks are a common persistence mechanism.",
                ev));
        }

        private void AnalyzeAuditProcessCreation(WindowsAuditEvent ev, List<Alert> alerts)
        {
            string text = ev.SearchText;
            EncodedCommandFinding encoded = CommandLineRules.FindEncodedCommand(text, config);
            if (encoded.Detected)
            {
                alerts.Add(Alert.FromWindowsEvent(
                    "AUDIT-PROC-ENCODED-CLI",
                    "Audit process creation captured encoded command",
                    88,
                    "Windows process-creation audit includes encoded/base64-like content. Reason: " + encoded.Reason + ". DecodedPreview: " + encoded.DecodedPreview,
                    "Review the full command line, parent process, and decoded payload.",
                    ev));
            }
            else if (IsSuspiciousCommandText(text))
            {
                alerts.Add(Alert.FromWindowsEvent(
                    "AUDIT-PROC-SUSPICIOUS-CLI",
                    "Audit process creation captured suspicious command",
                    72,
                    "Windows process-creation audit includes terms commonly associated with staging, download, or stealth.",
                    "Review parent process and user context. This can indicate a loader chain before network activity is visible.",
                    ev));
            }
        }

        private void AnalyzePersistence(List<PersistenceItem> items, List<Alert> alerts)
        {
            foreach (PersistenceItem item in items)
            {
                if (!state.MarkEventSeen("persistence|" + item.Identity)) continue;

                bool firstSeen = reputationCache.Observe("persistence", item.Identity, item.EntitySummary);
                bool trustedPersistence = IsTrustedPersistence(item);
                bool knownRmm = IsKnownRmmText(item.SearchText);
                bool highRiskCommand = IsHighRiskPersistenceCommandText(item.SearchText);
                bool encodedOrSuspiciousCommand = IsSuspiciousCommandText(item.Command);
                bool userWritable = IsUserWritableText(item.SearchText);
                bool lolbin = IsLolbinText(item.SearchText);
                bool suspicious = knownRmm || highRiskCommand || userWritable ||
                    (!trustedPersistence && (encodedOrSuspiciousCommand || lolbin));

                if (suspicious && firstSeen)
                {
                    alerts.Add(Alert.FromPersistenceItem(
                        "PERSIST-FIRST-SEEN-SUSPICIOUS",
                        "Suspicious first-seen persistence item",
                        knownRmm ? 92 : 78,
                        "A first-seen persistence item references suspicious command text, a user-writable path, a LOLBin, or remote management tooling.",
                        "Confirm the item is authorized. Remove it and preserve the command/path if it is unexpected.",
                        item));
                }
                else if (firstSeen && !config.BaselineLearningMode)
                {
                    alerts.Add(Alert.FromPersistenceItem(
                        "PERSIST-FIRST-SEEN",
                        "First-seen persistence item",
                        40,
                        "A persistence location contains an item not previously seen by the local reputation cache.",
                        "Low severity by itself. Review during baseline tuning and investigate if it appears near other alerts.",
                        item));
                }

                if (firstSeen || !config.BaselineLearningMode)
                {
                    alerts.AddRange(customRuleEngine.AnalyzePersistence(item));
                }
            }
        }

        private void AnalyzeProcessReputation(List<SysmonProcessEvent> processes, List<Alert> alerts)
        {
            foreach (SysmonProcessEvent process in processes)
            {
                if (!state.MarkEventSeen("host-process|" + process.RecordId.ToString(CultureInfo.InvariantCulture))) continue;

                string sha256 = ExtractSha256(process.Hashes);
                string key = String.IsNullOrWhiteSpace(sha256) ? process.Image : sha256;
                bool firstSeen = reputationCache.Observe("process", key, process.EntitySummary);
                bool userWritable = FileSystemRules.IsUserWritablePath(process.Image, config);
                bool suspiciousCommand = IsSuspiciousCommandText(process.CommandLine);
                bool suspiciousParent = config.SuspiciousParentProcesses.Contains(process.ParentProcessName);
                bool knownRmm = config.KnownRmmProcesses.Contains(process.ProcessName);

                if (knownRmm && firstSeen)
                {
                    alerts.Add(Alert.FromProcessEvent(
                        "REPUTATION-FIRST-SEEN-RMM",
                        "First-seen remote management executable",
                        86,
                        "A newly observed process hash/path matches a configured remote management or RAT-like tool name.",
                        "Confirm this tool is approved. Unauthorized RMM tools are frequently used for persistent access.",
                        process));
                }
                else if (firstSeen && userWritable && (suspiciousCommand || suspiciousParent))
                {
                    alerts.Add(Alert.FromProcessEvent(
                        "REPUTATION-FIRST-SEEN-USERPATH",
                        "First-seen executable from user-writable path",
                        78,
                        "A newly observed process hash/path launched from a user-writable location and has suspicious command or parent context.",
                        "Inspect the file hash, signer, parent process, and any persistence locations.",
                        process));
                }

                alerts.AddRange(customRuleEngine.AnalyzeProcess(process));
            }
        }

        private void AnalyzeCustomNetworkRules(List<NetworkEndpoint> endpoints, List<Alert> alerts)
        {
            foreach (NetworkEndpoint endpoint in endpoints)
            {
                if (!state.MarkEventSeen("custom-network|" + endpoint.ConnectionKey)) continue;
                alerts.AddRange(customRuleEngine.AnalyzeEndpoint(endpoint));
            }
        }

        private void RecordFailedLogon(string remote, DateTime timestampUtc)
        {
            List<DateTime> values;
            if (!failedLogonsByRemote.TryGetValue(remote, out values))
            {
                values = new List<DateTime>();
                failedLogonsByRemote[remote] = values;
            }

            values.Add(timestampUtc);
        }

        private int CountRecentFailedLogons(string remote, DateTime timestampUtc)
        {
            List<DateTime> values;
            if (!failedLogonsByRemote.TryGetValue(remote, out values)) return 0;

            for (int i = values.Count - 1; i >= 0; i--)
            {
                if ((timestampUtc - values[i]).TotalMinutes > 10)
                {
                    values.RemoveAt(i);
                }
            }

            return values.Count;
        }

        private bool IsSuspiciousCommandText(string text)
        {
            if (FileSystemRules.ContainsAny(text, config.SuspiciousCommandLineTerms)) return true;
            EncodedCommandFinding encoded = CommandLineRules.FindEncodedCommand(text, config);
            return encoded.Detected;
        }

        private bool IsHighRiskPersistenceCommandText(string text)
        {
            EncodedCommandFinding encoded = CommandLineRules.FindEncodedCommand(text, config);
            if (encoded.Detected) return true;

            return ContainsAny(
                text,
                "-encodedcommand",
                "-enc ",
                "frombase64string",
                "downloadstring",
                "downloadfile",
                "invoke-webrequest",
                " iwr ",
                "curl ",
                "wget ",
                "bitsadmin",
                "certutil",
                "http://",
                "https://",
                " -nop",
                " -noprofile",
                " -w hidden",
                " -windowstyle hidden",
                "executionpolicy bypass",
                "-ep bypass",
                "javascript:",
                "vbscript:");
        }

        private bool IsUserWritableText(string text)
        {
            return ContainsConfiguredIndicator(text, config.UserWritablePathIndicators);
        }

        private bool IsTrustedPersistence(PersistenceItem item)
        {
            return IsTrustedPersistenceText(item.Name, item.Path, item.Command);
        }

        private bool IsTrustedPersistenceText(string nameValue, string pathValue, string commandValue)
        {
            string name = nameValue ?? "";
            string path = pathValue ?? "";
            string command = commandValue ?? "";

            bool trustedName = false;
            foreach (string prefix in config.TrustedPersistenceNamePrefixes)
            {
                if (!String.IsNullOrWhiteSpace(prefix) &&
                    name.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
                {
                    trustedName = true;
                    break;
                }
            }

            bool trustedPath = ContainsConfiguredIndicator(path, config.TrustedPersistencePathIndicators) ||
                ContainsConfiguredIndicator(command, config.TrustedPersistencePathIndicators);

            return trustedName && trustedPath;
        }

        private bool IsKnownRmmText(string text)
        {
            foreach (string process in config.KnownRmmProcesses)
            {
                if (ContainsProcessToken(text, process))
                {
                    return true;
                }
            }

            return false;
        }

        private bool IsLolbinText(string text)
        {
            foreach (string process in config.LolbinProcesses)
            {
                if (ContainsProcessToken(text, process))
                {
                    return true;
                }
            }

            return false;
        }

        private static bool ContainsConfiguredIndicator(string text, HashSet<string> indicators)
        {
            if (String.IsNullOrWhiteSpace(text)) return false;

            foreach (string indicator in indicators)
            {
                if (!String.IsNullOrWhiteSpace(indicator) &&
                    text.IndexOf(indicator, StringComparison.OrdinalIgnoreCase) >= 0)
                {
                    return true;
                }
            }

            return false;
        }

        private static bool ContainsAny(string text, params string[] terms)
        {
            if (String.IsNullOrWhiteSpace(text)) return false;

            foreach (string term in terms)
            {
                if (!String.IsNullOrWhiteSpace(term) &&
                    text.IndexOf(term, StringComparison.OrdinalIgnoreCase) >= 0)
                {
                    return true;
                }
            }

            return false;
        }

        private static bool ContainsProcessToken(string text, string processName)
        {
            if (String.IsNullOrWhiteSpace(text) || String.IsNullOrWhiteSpace(processName)) return false;

            int index = text.IndexOf(processName, StringComparison.OrdinalIgnoreCase);
            while (index >= 0)
            {
                int after = index + processName.Length;
                bool beforeOk = index == 0 || IsProcessTokenBoundary(text[index - 1]);
                bool afterOk = after >= text.Length || IsProcessTokenBoundary(text[after]);
                if (beforeOk && afterOk) return true;

                index = text.IndexOf(processName, index + 1, StringComparison.OrdinalIgnoreCase);
            }

            return false;
        }

        private static bool IsProcessTokenBoundary(char value)
        {
            return Char.IsWhiteSpace(value) ||
                value == '\\' ||
                value == '/' ||
                value == '"' ||
                value == '\'' ||
                value == '=' ||
                value == ',' ||
                value == ';' ||
                value == '(' ||
                value == ')';
        }

        private static bool IsRemoteAddress(string value)
        {
            if (String.IsNullOrWhiteSpace(value)) return false;
            string trimmed = value.Trim();
            return !trimmed.Equals("-", StringComparison.Ordinal) &&
                !trimmed.Equals("::1", StringComparison.OrdinalIgnoreCase) &&
                !trimmed.Equals("127.0.0.1", StringComparison.OrdinalIgnoreCase) &&
                !trimmed.Equals("localhost", StringComparison.OrdinalIgnoreCase);
        }

        private static string ExtractSha256(string hashes)
        {
            if (String.IsNullOrWhiteSpace(hashes)) return "";

            string[] parts = hashes.Split(',');
            foreach (string part in parts)
            {
                string trimmed = part.Trim();
                if (trimmed.StartsWith("SHA256=", StringComparison.OrdinalIgnoreCase))
                {
                    return trimmed.Substring("SHA256=".Length).Trim();
                }
            }

            return "";
        }
    }
}
