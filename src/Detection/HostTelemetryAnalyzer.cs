using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Web.Script.Serialization;

namespace ArcaneEDR
{
    internal sealed class HostTelemetryAnalyzer
    {
        private readonly MonitorConfig config;
        private readonly DetectionState state;
        private readonly ReputationCache reputationCache;
        private readonly CustomRuleEngine customRuleEngine;
        private readonly Dictionary<string, List<DateTime>> failedLogonsByRemote = new Dictionary<string, List<DateTime>>(StringComparer.OrdinalIgnoreCase);
        private readonly Dictionary<string, List<RemoteLogonObservation>> recentRemoteLogonsByUser = new Dictionary<string, List<RemoteLogonObservation>>(StringComparer.OrdinalIgnoreCase);
        private readonly Dictionary<string, DateTime> lastSpecialPrivilegeAlertByPrincipal = new Dictionary<string, DateTime>(StringComparer.OrdinalIgnoreCase);
        private readonly Dictionary<string, DateTime> recentExecutableFileDropsByPath = new Dictionary<string, DateTime>(StringComparer.OrdinalIgnoreCase);

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
            PruneRecentExecutableFileDrops(timestampUtc);
            AnalyzeFileEvents(snapshot.FileEvents, alerts);
            AnalyzeProcessReputation(snapshot.ProcessEvents, alerts);
            AnalyzeResponseProcessRespawns(snapshot.ProcessEvents, alerts);
            AnalyzeCustomNetworkRules(snapshot.Endpoints, alerts);

            return alerts;
        }

        private void AnalyzePowerShell(List<PowerShellEvent> events, List<Alert> alerts)
        {
            foreach (PowerShellEvent ev in events)
            {
                if (!state.MarkEventSeen("powershell|" + ev.CooldownKey)) continue;

                string text = ev.SearchText;
                if (IsPowerShellCmdletizationScaffolding(text) ||
                    IsPowerShellReleasePackagingScaffolding(text))
                {
                    continue;
                }

                EncodedCommandFinding encoded = CommandLineRules.FindEncodedCommand(text, config);
                bool suspiciousTerm = FileSystemRules.ContainsAny(text, config.SuspiciousCommandLineTerms);
                bool downloadCradle = ContainsAny(text, "downloadstring", "downloadfile", "invoke-webrequest", " iwr ", "curl ", "wget ", "bitsadmin", "certutil", "http://", "https://");
                bool defenderTamper = ContainsAny(text, "set-mppreference", "disableantispyware", "disablerealtimemonitoring", "add-mppreference", "exclusionpath", "exclusionprocess");
                bool stealth = ContainsAny(text, "-windowstyle hidden", "-w hidden", "-nop", "-noprofile", "executionpolicy bypass", "-ep bypass");
                bool persistence = ContainsAny(text, "new-service", "sc.exe create", "schtasks", "\\currentversion\\run", "startup");
                bool appInventory = encoded.Detected && IsPowerShellAppInventoryEnumeration(text);

                if (encoded.Detected)
                {
                    alerts.Add(Alert.FromPowerShellEvent(
                        appInventory ? "PS-ENCODED-APP-INVENTORY" : "PS-ENCODED-COMMAND",
                        appInventory ? "Encoded PowerShell app inventory observed" : "PowerShell encoded or obfuscated command detected",
                        appInventory ? 62 : 92,
                        appInventory
                            ? "PowerShell used encoded execution for app/process inventory telemetry. Reason: " + encoded.Reason + ". DecodedPreview: " + encoded.DecodedPreview
                            : "PowerShell telemetry includes encoded/base64-like content. Reason: " + encoded.Reason + ". DecodedPreview: " + encoded.DecodedPreview,
                        appInventory
                            ? "Confirm the parent/source is expected inventory tooling. Investigate if this appears outside known agent or browser workflows."
                            : "Review the decoded payload and parent process. Encoded PowerShell is common in loader and RAT staging activity.",
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
                else if (!appInventory && (downloadCradle || suspiciousTerm))
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

                AnalyzeAgentAdminPowerShell(ev, alerts);
                AnalyzeAgentSecretPowerShell(ev, alerts);
                AnalyzeAgentSupplyChainPowerShell(ev, alerts);
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
                    AnalyzeSuccessfulLogon(ev, timestampUtc, alerts);
                }
                else if (ev.EventId == 4672)
                {
                    AnalyzeSpecialPrivileges(ev, timestampUtc, alerts);
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

        private void AnalyzeSuccessfulLogon(WindowsAuditEvent ev, DateTime timestampUtc, List<Alert> alerts)
        {
            if (IsUnspecifiedRemoteAddress(ev.IpAddress))
            {
                if (ev.LogonType == "10" || ev.LogonType == "3")
                {
                    alerts.Add(Alert.FromWindowsEvent(
                        "AUTH-LOGON-UNSPECIFIED-SOURCE",
                        "Logon observed with unspecified source",
                        40,
                        "Windows reported a remote-style logon type with an unspecified source address such as 0.0.0.0.",
                        "Treat as local context unless it is unexpected for this machine. Hyper-V, local session brokering, and some Windows workflows can report unspecified source addresses.",
                        ev));
                }

                return;
            }

            if (!IsRemoteAddress(ev.IpAddress)) return;

            RecordRemoteLogon(ev, timestampUtc);
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

        private void AnalyzeSpecialPrivileges(WindowsAuditEvent ev, DateTime timestampUtc, List<Alert> alerts)
        {
            string principal = PrincipalFor(ev);
            RemoteLogonObservation remote = FindRecentRemoteLogon(principal, timestampUtc);
            if (remote != null)
            {
                alerts.Add(Alert.FromWindowsEvent(
                    "AUTH-REMOTE-SPECIAL-PRIVILEGES",
                    "Privileged logon near remote access",
                    72,
                    "Windows reported special privileges assigned to a logon session shortly after remote logon activity for the same account.",
                    "Confirm the account, source, and session were expected. Remote access plus special privileges is stronger hands-on-access context than a standalone 4672 event.",
                    ev));
                return;
            }

            if (!ShouldEmitStandaloneSpecialPrivilege(principal, timestampUtc))
            {
                return;
            }

            alerts.Add(Alert.FromWindowsEvent(
                "AUTH-SPECIAL-PRIVILEGES",
                "Privileged logon observed",
                35,
                "Windows reported special privileges assigned to a logon session without recent remote-logon correlation.",
                "Low severity by itself. Correlate with time of day, maintenance activity, process staging, persistence, or remote access before escalating.",
                ev));
        }

        private void AnalyzeServiceInstall(WindowsAuditEvent ev, List<Alert> alerts)
        {
            string text = ev.SearchText;
            PersistenceTrustResult trust = PersistenceTrust.Evaluate(config, ev.ServiceName, ev.ProcessName, ev.CommandLine, "");
            bool userWritable = IsUntrustedUserWritablePersistenceText(text, trust);
            bool suspicious = IsSuspiciousCommandText(text) || userWritable || IsKnownRmmText(text);
            bool trusted = !suspicious && trust.Trusted;

            alerts.Add(Alert.FromWindowsEvent(
                suspicious ? "PERSIST-SERVICE-INSTALL-SUSPICIOUS" : (trusted ? "PERSIST-SERVICE-INSTALL-TRUSTED" : "PERSIST-SERVICE-INSTALL"),
                suspicious ? "Suspicious service installation" : (trusted ? "Trusted-location service installation observed" : "Service installation observed"),
                suspicious ? 90 : (trusted ? 50 : 78),
                suspicious
                    ? "A new service was installed with command/path traits associated with RAT persistence or remote management tooling."
                    : (trusted
                        ? TrustedPersistenceBody("service installation", trust)
                        : "A new service installation was observed."),
                "Confirm the service owner, binary path, signer, and install source. Unauthorized services are common persistence mechanisms.",
                ev));
        }

        private void AnalyzeScheduledTaskEvent(WindowsAuditEvent ev, List<Alert> alerts)
        {
            string text = ev.SearchText;
            PersistenceTrustResult trust = PersistenceTrust.Evaluate(config, ev.TaskName, ev.ProcessName, ev.CommandLine, "");
            bool userWritable = IsUntrustedUserWritablePersistenceText(text, trust);
            bool suspicious = IsSuspiciousCommandText(text) || userWritable || IsKnownRmmText(text);
            bool trusted = !suspicious && trust.Trusted;

            alerts.Add(Alert.FromWindowsEvent(
                suspicious ? "PERSIST-SCHEDULED-TASK-SUSPICIOUS" : (trusted ? "PERSIST-SCHEDULED-TASK-TRUSTED" : "PERSIST-SCHEDULED-TASK-CHANGE"),
                suspicious ? "Suspicious scheduled task change" : (trusted ? "Trusted-location scheduled task change observed" : "Scheduled task change observed"),
                suspicious ? 85 : (trusted ? 45 : 70),
                suspicious
                    ? "A scheduled task was created or updated with command/path traits associated with staging or RAT persistence."
                    : (trusted
                        ? TrustedPersistenceBody("scheduled task change", trust)
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

            AnalyzeAgentAdminWindowsProcess(ev, alerts);
            AnalyzeAgentSecretWindowsProcess(ev, alerts);
            AnalyzeAgentSupplyChainWindowsProcess(ev, alerts);
        }

        private void AnalyzeAgentAdminPowerShell(PowerShellEvent ev, List<Alert> alerts)
        {
            string text = CombineText(
                ev == null ? "" : ev.SearchText,
                ev == null ? "" : ev.EntitySummary,
                ev == null ? "" : ev.ProcessCommandLine,
                ev == null ? "" : ev.ParentCommandLine,
                ev == null ? "" : ev.ProcessPath,
                ev == null ? "" : ev.ParentProcessPath);
            AgentAdminCommandFinding finding = FindAgentAdminCommand(text);
            if (!finding.Detected) return;

            Alert alert = Alert.FromPowerShellEvent(
                "AGENT-ADMIN-COMMAND",
                "Agent-adjacent admin command observed",
                finding.Score,
                AgentAdminCommandBody(finding, "PowerShell telemetry"),
                "Confirm this was intended agent maintenance. If expected, use the constrained admin-task bridge or tune AgentApprovedAdminTaskNames and maintenance context locally.",
                ev);
            alert.Category = "Agent";
            alerts.Add(alert);
        }

        private void AnalyzeAgentAdminWindowsProcess(WindowsAuditEvent ev, List<Alert> alerts)
        {
            string text = CombineText(ev == null ? "" : ev.SearchText, ev == null ? "" : ev.EntitySummary);
            AgentAdminCommandFinding finding = FindAgentAdminCommand(text);
            if (!finding.Detected) return;

            Alert alert = Alert.FromWindowsEvent(
                "AGENT-ADMIN-COMMAND",
                "Agent-adjacent admin command observed",
                finding.Score,
                AgentAdminCommandBody(finding, "Windows process-creation audit"),
                "Confirm this was intended agent maintenance. If expected, use the constrained admin-task bridge or tune AgentApprovedAdminTaskNames and maintenance context locally.",
                ev);
            alert.Category = "Agent";
            alerts.Add(alert);
        }

        private void AnalyzeAgentAdminProcess(SysmonProcessEvent process, List<Alert> alerts)
        {
            string text = CombineText(process == null ? "" : process.EntitySummary);
            AgentAdminCommandFinding finding = FindAgentAdminCommand(text);
            if (!finding.Detected) return;

            Alert alert = Alert.FromProcessEvent(
                "AGENT-ADMIN-COMMAND",
                "Agent-adjacent admin command observed",
                finding.Score,
                AgentAdminCommandBody(finding, "Sysmon process telemetry"),
                "Confirm this was intended agent maintenance. If expected, use the constrained admin-task bridge or tune AgentApprovedAdminTaskNames and maintenance context locally.",
                process);
            alert.Category = "Agent";
            alerts.Add(alert);
        }

        private void AnalyzeAgentSecretPowerShell(PowerShellEvent ev, List<Alert> alerts)
        {
            string text = CombineText(
                ev == null ? "" : ev.SearchText,
                ev == null ? "" : ev.EntitySummary,
                ev == null ? "" : ev.ProcessCommandLine,
                ev == null ? "" : ev.ParentCommandLine,
                ev == null ? "" : ev.ProcessPath,
                ev == null ? "" : ev.ParentProcessPath);
            AgentGuardrailFinding finding = FindAgentSecretReference(text);
            if (!finding.Detected) return;

            Alert alert = Alert.FromPowerShellEvent(
                "AGENT-SECRET-REFERENCE",
                "Agent-adjacent secret reference observed",
                finding.Score,
                AgentSecretReferenceBody(finding, "PowerShell telemetry"),
                "Confirm the agent did not copy, expose, or modify credentials. Rotate affected secrets if this was not intended.",
                ev);
            alert.Category = "Agent";
            alerts.Add(alert);
        }

        private void AnalyzeAgentSecretWindowsProcess(WindowsAuditEvent ev, List<Alert> alerts)
        {
            string text = CombineText(ev == null ? "" : ev.SearchText, ev == null ? "" : ev.EntitySummary);
            AgentGuardrailFinding finding = FindAgentSecretReference(text);
            if (!finding.Detected) return;

            Alert alert = Alert.FromWindowsEvent(
                "AGENT-SECRET-REFERENCE",
                "Agent-adjacent secret reference observed",
                finding.Score,
                AgentSecretReferenceBody(finding, "Windows process-creation audit"),
                "Confirm the agent did not copy, expose, or modify credentials. Rotate affected secrets if this was not intended.",
                ev);
            alert.Category = "Agent";
            alerts.Add(alert);
        }

        private void AnalyzeAgentSecretProcess(SysmonProcessEvent process, List<Alert> alerts)
        {
            string text = CombineText(process == null ? "" : process.EntitySummary);
            AgentGuardrailFinding finding = FindAgentSecretReference(text);
            if (!finding.Detected) return;

            Alert alert = Alert.FromProcessEvent(
                "AGENT-SECRET-REFERENCE",
                "Agent-adjacent secret reference observed",
                finding.Score,
                AgentSecretReferenceBody(finding, "Sysmon process telemetry"),
                "Confirm the agent did not copy, expose, or modify credentials. Rotate affected secrets if this was not intended.",
                process);
            alert.Category = "Agent";
            alerts.Add(alert);
        }

        private void AnalyzeAgentSupplyChainPowerShell(PowerShellEvent ev, List<Alert> alerts)
        {
            string text = CombineText(
                ev == null ? "" : ev.SearchText,
                ev == null ? "" : ev.EntitySummary,
                ev == null ? "" : ev.ProcessCommandLine,
                ev == null ? "" : ev.ParentCommandLine,
                ev == null ? "" : ev.ProcessPath,
                ev == null ? "" : ev.ParentProcessPath);
            AgentGuardrailFinding finding = FindAgentSupplyChainCommand(text);
            if (!finding.Detected) return;

            Alert alert = Alert.FromPowerShellEvent(
                "AGENT-SUPPLY-CHAIN-COMMAND",
                "Agent-adjacent package or download command observed",
                finding.Score,
                AgentSupplyChainBody(finding, "PowerShell telemetry"),
                "Review the package source, downloaded script, and workspace context. Use maintenance markers for expected install or publish windows.",
                ev);
            alert.Category = "Agent";
            alerts.Add(alert);
        }

        private void AnalyzeAgentSupplyChainWindowsProcess(WindowsAuditEvent ev, List<Alert> alerts)
        {
            string text = CombineText(ev == null ? "" : ev.SearchText, ev == null ? "" : ev.EntitySummary);
            AgentGuardrailFinding finding = FindAgentSupplyChainCommand(text);
            if (!finding.Detected) return;

            Alert alert = Alert.FromWindowsEvent(
                "AGENT-SUPPLY-CHAIN-COMMAND",
                "Agent-adjacent package or download command observed",
                finding.Score,
                AgentSupplyChainBody(finding, "Windows process-creation audit"),
                "Review the package source, downloaded script, and workspace context. Use maintenance markers for expected install or publish windows.",
                ev);
            alert.Category = "Agent";
            alerts.Add(alert);
        }

        private void AnalyzeAgentSupplyChainProcess(SysmonProcessEvent process, List<Alert> alerts)
        {
            string text = CombineText(process == null ? "" : process.EntitySummary);
            AgentGuardrailFinding finding = FindAgentSupplyChainCommand(text);
            if (!finding.Detected) return;

            Alert alert = Alert.FromProcessEvent(
                "AGENT-SUPPLY-CHAIN-COMMAND",
                "Agent-adjacent package or download command observed",
                finding.Score,
                AgentSupplyChainBody(finding, "Sysmon process telemetry"),
                "Review the package source, downloaded script, and workspace context. Use maintenance markers for expected install or publish windows.",
                process);
            alert.Category = "Agent";
            alerts.Add(alert);
        }

        private AgentAdminCommandFinding FindAgentAdminCommand(string text)
        {
            AgentAdminCommandFinding finding = new AgentAdminCommandFinding();
            if (String.IsNullOrWhiteSpace(text) ||
                !config.EnableAgentProfile ||
                !config.EnableAgentAdminCommandGuardrails)
            {
                return finding;
            }

            string normalized = NormalizePathText(text);
            if (!IsAgentInitiatedText(normalized)) return finding;

            string term = FirstConfiguredTerm(normalized, config.AgentAdminCommandTerms);
            if (String.IsNullOrWhiteSpace(term)) return finding;

            finding.Approved = IsApprovedAgentAdminText(normalized);
            if (finding.Approved) return finding;

            finding.Detected = true;
            finding.Term = term;
            finding.CommandFamily = AgentAdminCommandFamily(term);
            finding.Score = ClampScore(config.AgentAdminCommandMinimumScore);
            return finding;
        }

        private string AgentAdminCommandBody(AgentAdminCommandFinding finding, string source)
        {
            return source + " includes an agent-initiated admin, elevation, persistence, firewall, security-control, registry, service, scheduled-task, or ACL command outside configured approved admin tasks." +
                " CommandFamily=" + finding.CommandFamily +
                " MatchedTerm=" + SafeReason(finding.Term) +
                " ResponseMode=AlertOnly.";
        }

        private AgentGuardrailFinding FindAgentSecretReference(string text)
        {
            AgentGuardrailFinding finding = new AgentGuardrailFinding();
            if (String.IsNullOrWhiteSpace(text) ||
                !config.EnableAgentProfile ||
                !config.EnableAgentSecretReferenceGuardrails)
            {
                return finding;
            }

            string normalized = NormalizePathText(text);
            if (!IsAgentInitiatedText(normalized)) return finding;

            string term = FirstConfiguredTerm(normalized, config.AgentSecretReferenceTerms);
            if (String.IsNullOrWhiteSpace(term))
            {
                term = FirstConfiguredTerm(normalized, config.AgentSecretIndicatorTerms);
            }

            if (String.IsNullOrWhiteSpace(term)) return finding;

            finding.Detected = true;
            finding.Term = term;
            finding.CommandFamily = AgentSecretReferenceFamily(term);
            finding.Score = ClampScore(config.AgentSecretReferenceMinimumScore);
            return finding;
        }

        private AgentGuardrailFinding FindAgentSupplyChainCommand(string text)
        {
            AgentGuardrailFinding finding = new AgentGuardrailFinding();
            if (String.IsNullOrWhiteSpace(text) ||
                !config.EnableAgentProfile ||
                !config.EnableAgentSupplyChainGuardrails)
            {
                return finding;
            }

            string normalized = NormalizePathText(text);
            if (!IsAgentInitiatedText(normalized)) return finding;

            string term = FirstConfiguredTerm(normalized, config.AgentSupplyChainTerms);
            if (String.IsNullOrWhiteSpace(term)) return finding;

            finding.Detected = true;
            finding.Term = term;
            finding.CommandFamily = AgentSupplyChainFamily(term);
            finding.Score = ClampScore(config.AgentSupplyChainMinimumScore);
            return finding;
        }

        private string AgentSecretReferenceBody(AgentGuardrailFinding finding, string source)
        {
            return source + " includes an agent-initiated reference to a configured secret, credential, SSH key, certificate, token, or browser credential-store indicator." +
                " SecretReferenceFamily=" + finding.CommandFamily +
                " MatchedTerm=" + SafeReason(finding.Term) +
                " ResponseMode=AlertOnly.";
        }

        private string AgentSupplyChainBody(AgentGuardrailFinding finding, string source)
        {
            return source + " includes an agent-initiated package install, source clone, download, install script, or expression-execution indicator." +
                " SupplyChainFamily=" + finding.CommandFamily +
                " MatchedTerm=" + SafeReason(finding.Term) +
                " ResponseMode=AlertOnly.";
        }

        private static string AgentSecretReferenceFamily(string term)
        {
            string value = term == null ? "" : term.ToLowerInvariant();
            if (value.IndexOf("id_rsa", StringComparison.OrdinalIgnoreCase) >= 0 ||
                value.IndexOf("id_ed25519", StringComparison.OrdinalIgnoreCase) >= 0 ||
                value.IndexOf("ssh", StringComparison.OrdinalIgnoreCase) >= 0) return "ssh-material";
            if (value.IndexOf(".pem", StringComparison.OrdinalIgnoreCase) >= 0 ||
                value.IndexOf(".pfx", StringComparison.OrdinalIgnoreCase) >= 0 ||
                value.IndexOf("private_key", StringComparison.OrdinalIgnoreCase) >= 0) return "key-or-certificate";
            if (value.IndexOf("chrome", StringComparison.OrdinalIgnoreCase) >= 0 ||
                value.IndexOf("edge", StringComparison.OrdinalIgnoreCase) >= 0 ||
                value.IndexOf("firefox", StringComparison.OrdinalIgnoreCase) >= 0) return "browser-credential-store";
            if (value.IndexOf("aws_", StringComparison.OrdinalIgnoreCase) >= 0 ||
                value.IndexOf("azure_", StringComparison.OrdinalIgnoreCase) >= 0 ||
                value.IndexOf("gcloud", StringComparison.OrdinalIgnoreCase) >= 0) return "cloud-secret";
            if (value.IndexOf("token", StringComparison.OrdinalIgnoreCase) >= 0 ||
                value.IndexOf("secret", StringComparison.OrdinalIgnoreCase) >= 0 ||
                value.IndexOf("apikey", StringComparison.OrdinalIgnoreCase) >= 0 ||
                value.IndexOf("api_key", StringComparison.OrdinalIgnoreCase) >= 0) return "token-or-api-key";
            return "secret-reference";
        }

        private static string AgentSupplyChainFamily(string term)
        {
            string value = term == null ? "" : term.ToLowerInvariant();
            if (value.IndexOf("npm", StringComparison.OrdinalIgnoreCase) >= 0 ||
                value.IndexOf("npx", StringComparison.OrdinalIgnoreCase) >= 0 ||
                value.IndexOf("pnpm", StringComparison.OrdinalIgnoreCase) >= 0 ||
                value.IndexOf("yarn", StringComparison.OrdinalIgnoreCase) >= 0) return "node-package-manager";
            if (value.IndexOf("pip", StringComparison.OrdinalIgnoreCase) >= 0) return "python-package-manager";
            if (value.IndexOf("git clone", StringComparison.OrdinalIgnoreCase) >= 0) return "source-clone";
            if (value.IndexOf("curl", StringComparison.OrdinalIgnoreCase) >= 0 ||
                value.IndexOf("webrequest", StringComparison.OrdinalIgnoreCase) >= 0 ||
                value.IndexOf("download", StringComparison.OrdinalIgnoreCase) >= 0 ||
                value.IndexOf("wget", StringComparison.OrdinalIgnoreCase) >= 0 ||
                value.IndexOf("restmethod", StringComparison.OrdinalIgnoreCase) >= 0) return "download";
            if (value.IndexOf("iex", StringComparison.OrdinalIgnoreCase) >= 0 ||
                value.IndexOf("expression", StringComparison.OrdinalIgnoreCase) >= 0) return "download-and-execute";
            if (value.IndexOf("install", StringComparison.OrdinalIgnoreCase) >= 0 ||
                value.IndexOf("postinstall", StringComparison.OrdinalIgnoreCase) >= 0) return "install-script";
            return "supply-chain";
        }

        private bool IsAgentInitiatedText(string text)
        {
            if (ContainsConfiguredRootText(text, config.AgentWorkspaceRoots)) return true;
            if (ContainsConfiguredRootText(text, config.AgentPublishRoots)) return true;
            if (ContainsProcessFieldAny(text, config.AgentProcessNames, "process=", "process_name=", "parent=", "parent_process=", "parent_process_name=", "host_application=")) return true;
            if (ContainsProcessFieldAny(text, config.AgentProcessNames, "parent_image=", "parent_path=", "parent_command_line=", "process_command_line=")) return true;

            bool childProcess = ContainsProcessFieldAny(text, config.AgentChildProcessNames, "process=", "process_name=");
            bool packageTool = ContainsProcessFieldAny(text, config.AgentPackageManagerProcesses, "process=", "process_name=");
            if ((childProcess || packageTool) &&
                (ContainsProcessFieldAny(text, config.AgentProcessNames, "parent=", "parent_process=", "parent_process_name=") ||
                 ContainsConfiguredRootText(text, config.AgentWorkspaceRoots) ||
                 ContainsConfiguredRootText(text, config.AgentPublishRoots)))
            {
                return true;
            }

            return false;
        }

        private bool IsApprovedAgentAdminText(string text)
        {
            foreach (string taskName in config.AgentApprovedAdminTaskNames)
            {
                if (String.IsNullOrWhiteSpace(taskName)) continue;
                string normalizedTask = NormalizePathText(taskName);
                if (text.IndexOf(normalizedTask, StringComparison.OrdinalIgnoreCase) >= 0) return true;

                string compactTask = normalizedTask.Trim('\\');
                if (compactTask.Length > 0 &&
                    text.IndexOf(compactTask, StringComparison.OrdinalIgnoreCase) >= 0)
                {
                    return true;
                }
            }

            return false;
        }

        private static string AgentAdminCommandFamily(string term)
        {
            string value = term == null ? "" : term.ToLowerInvariant();
            if (value.IndexOf("firewall", StringComparison.OrdinalIgnoreCase) >= 0 ||
                value.IndexOf("advfirewall", StringComparison.OrdinalIgnoreCase) >= 0) return "firewall";
            if (value.IndexOf("schtasks", StringComparison.OrdinalIgnoreCase) >= 0 ||
                value.IndexOf("scheduledtask", StringComparison.OrdinalIgnoreCase) >= 0) return "scheduled-task";
            if (value.IndexOf("service", StringComparison.OrdinalIgnoreCase) >= 0 ||
                value.IndexOf("sc ", StringComparison.OrdinalIgnoreCase) >= 0 ||
                value.IndexOf("sc.exe", StringComparison.OrdinalIgnoreCase) >= 0) return "service";
            if (value.IndexOf("icacls", StringComparison.OrdinalIgnoreCase) >= 0 ||
                value.IndexOf("takeown", StringComparison.OrdinalIgnoreCase) >= 0 ||
                value.IndexOf("set-acl", StringComparison.OrdinalIgnoreCase) >= 0) return "acl";
            if (value.IndexOf("runas", StringComparison.OrdinalIgnoreCase) >= 0) return "elevation";
            if (value.IndexOf("mppreference", StringComparison.OrdinalIgnoreCase) >= 0 ||
                value.IndexOf("defender", StringComparison.OrdinalIgnoreCase) >= 0) return "security-control";
            if (value.IndexOf("reg ", StringComparison.OrdinalIgnoreCase) >= 0 ||
                value.IndexOf("currentversion", StringComparison.OrdinalIgnoreCase) >= 0) return "registry";
            return "admin-command";
        }

        private static string FirstConfiguredTerm(string text, HashSet<string> terms)
        {
            if (String.IsNullOrWhiteSpace(text) || terms == null) return "";
            foreach (string term in terms)
            {
                if (!String.IsNullOrWhiteSpace(term) &&
                    text.IndexOf(NormalizePathText(term), StringComparison.OrdinalIgnoreCase) >= 0)
                {
                    return term;
                }
            }

            return "";
        }

        private static bool ContainsAnyConfigured(string text, HashSet<string> terms)
        {
            if (String.IsNullOrWhiteSpace(text) || terms == null) return false;
            foreach (string term in terms)
            {
                if (!String.IsNullOrWhiteSpace(term) &&
                    text.IndexOf(NormalizePathText(term), StringComparison.OrdinalIgnoreCase) >= 0)
                {
                    return true;
                }
            }

            return false;
        }

        private static bool ContainsProcessFieldAny(string text, HashSet<string> values, params string[] fieldNames)
        {
            if (String.IsNullOrWhiteSpace(text) || values == null || fieldNames == null) return false;
            foreach (string fieldName in fieldNames)
            {
                foreach (string value in values)
                {
                    if (ContainsProcessField(text, fieldName, value)) return true;
                }
            }

            return false;
        }

        private static bool ContainsProcessField(string text, string fieldName, string expected)
        {
            if (String.IsNullOrWhiteSpace(text) || String.IsNullOrWhiteSpace(fieldName) || String.IsNullOrWhiteSpace(expected)) return false;

            int index = text.IndexOf(fieldName, StringComparison.OrdinalIgnoreCase);
            while (index >= 0)
            {
                int start = index + fieldName.Length;
                if (ValueMatchesAt(text, start, expected)) return true;
                index = text.IndexOf(fieldName, index + fieldName.Length, StringComparison.OrdinalIgnoreCase);
            }

            return false;
        }

        private static bool ValueMatchesAt(string text, int start, string expected)
        {
            int index = start;
            while (index < text.Length && Char.IsWhiteSpace(text[index]))
            {
                index++;
            }

            if (index < text.Length && text[index] == '"') index++;
            if (index + expected.Length > text.Length) return false;
            if (!text.Substring(index, expected.Length).Equals(expected, StringComparison.OrdinalIgnoreCase)) return false;

            int after = index + expected.Length;
            return after >= text.Length || IsTokenBoundary(text[after]);
        }

        private static bool IsTokenBoundary(char value)
        {
            return Char.IsWhiteSpace(value) ||
                value == '"' ||
                value == '\'' ||
                value == ',' ||
                value == ';' ||
                value == ')' ||
                value == '(' ||
                value == '|' ||
                value == '\r' ||
                value == '\n';
        }

        private static int ClampScore(int score)
        {
            if (score < 0) return 0;
            if (score > 100) return 100;
            return score;
        }

        private static string SafeReason(string value)
        {
            if (String.IsNullOrWhiteSpace(value)) return "unknown";
            string result = value.Trim()
                .Replace("\r", "")
                .Replace("\n", "")
                .Replace(",", "_")
                .Replace(";", "_")
                .Replace("|", "_");
            return result.Length <= 80 ? result : result.Substring(0, 80);
        }

        private static string CombineText(params string[] values)
        {
            List<string> parts = new List<string>();
            foreach (string value in values)
            {
                if (!String.IsNullOrWhiteSpace(value)) parts.Add(value);
            }

            return String.Join(" ", parts.ToArray());
        }

        private void AnalyzePersistence(List<PersistenceItem> items, List<Alert> alerts)
        {
            foreach (PersistenceItem item in items)
            {
                if (!state.MarkEventSeen("persistence|" + item.Identity)) continue;

                PersistenceTrustResult trust = PersistenceTrust.Evaluate(config, item.Name, item.Path, item.Command, item.Signer);
                if (String.IsNullOrWhiteSpace(item.Signer)) item.Signer = trust.Signer;

                bool firstSeen = reputationCache.Observe("persistence", item.Identity, item.EntitySummary);
                bool trustedPersistence = trust.Trusted;
                bool knownRmm = IsKnownRmmText(item.SearchText);
                bool highRiskCommand = IsHighRiskPersistenceCommandText(item.SearchText);
                bool encodedOrSuspiciousCommand = IsSuspiciousCommandText(item.Command);
                bool userWritable = IsUntrustedUserWritablePersistenceText(item.SearchText, trust);
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

                if (config.EnableHighSignalFileDetection && IsRecentExecutableFileDrop(process.Image, process.TimestampUtc))
                {
                    alerts.Add(Alert.FromProcessEvent(
                        "FILE-DROP-THEN-EXECUTION",
                        "Recently dropped high-risk file was executed",
                        88,
                        "A process executed from a path that Sysmon recently observed as an executable or script drop in a high-risk file location.",
                        "Inspect the file, parent process, writer process, and any persistence or network activity. Treat as suspicious unless this was an intentional simulation or installer.",
                        process));
                }

                AnalyzeAgentAdminProcess(process, alerts);
                AnalyzeAgentSecretProcess(process, alerts);
                AnalyzeAgentSupplyChainProcess(process, alerts);
                alerts.AddRange(customRuleEngine.AnalyzeProcess(process));
            }
        }

        private void AnalyzeFileEvents(List<SysmonFileEvent> events, List<Alert> alerts)
        {
            if (!config.EnableHighSignalFileDetection) return;

            foreach (SysmonFileEvent ev in events)
            {
                if (!state.MarkEventSeen("sysmon-file|" + ev.RecordId.ToString(CultureInfo.InvariantCulture))) continue;

                string target = ev.TargetFilename ?? "";
                bool highRiskPath = ContainsConfiguredIndicator(target, config.HighRiskFilePathIndicators);
                bool executableOrScript = IsHighRiskFileExtension(target);
                bool sensitiveName = IsSensitiveFilename(target);
                bool suspiciousWriter = IsSuspiciousFileWriter(ev);
                bool expectedSignedWriter = IsExpectedSignedFileWriter(ev);
                bool agentWriter = IsAgentFileWriter(ev);
                bool outsideAgentRoots = IsAgentOutsideApprovedRoots(agentWriter, target);
                bool skipExpectedBrowserExtension = IsBrowserExtensionPath(target) &&
                    expectedSignedWriter &&
                    !suspiciousWriter &&
                    !outsideAgentRoots;

                if (highRiskPath && executableOrScript && !skipExpectedBrowserExtension)
                {
                    bool elevated = suspiciousWriter || outsideAgentRoots;
                    RecordRecentExecutableFileDrop(ev);
                    alerts.Add(Alert.FromFileEvent(
                        elevated ? "FILE-HIGH-RISK-DROP-SUSPICIOUS-WRITER" : "FILE-HIGH-RISK-EXECUTABLE-DROP",
                        elevated ? "Suspicious writer created high-risk executable file" : "Executable file created in high-risk location",
                        elevated ? 82 : 65,
                        elevated
                            ? "Sysmon observed an executable or script file created in a persistence-adjacent or extension location by a suspicious writer, remote-management tool, LOLBin, unsigned user-writable process, or configured agent process outside approved roots."
                            : "Sysmon observed an executable or script file created in a persistence-adjacent or extension location.",
                        "Confirm the writer process and target path. Remove the file if unexpected, and correlate with process execution, persistence, PowerShell, and network alerts.",
                        ev));
                }
                else if (executableOrScript && outsideAgentRoots)
                {
                    RecordRecentExecutableFileDrop(ev);
                    alerts.Add(Alert.FromFileEvent(
                        "FILE-AGENT-EXECUTABLE-DROP-OUTSIDE-ROOT",
                        "Agent-adjacent executable drop outside approved roots",
                        72,
                        "A configured agent process or child/package tool created an executable or script outside configured agent workspace and publish roots.",
                        "Confirm whether the path is an approved working or publish location. If expected, tune AgentWorkspaceRoots or AgentPublishRoots locally.",
                        ev));
                }

                if (sensitiveName && (suspiciousWriter || outsideAgentRoots))
                {
                    alerts.Add(Alert.FromFileEvent(
                        "FILE-SENSITIVE-MATERIAL-TOUCHED",
                        "Sensitive-looking file touched by suspicious context",
                        outsideAgentRoots ? 82 : 78,
                        "Sysmon observed a file-create event for a sensitive-looking filename such as a token, credential, SSH key, certificate, or .env file, and the writer had suspicious or out-of-profile context.",
                        "Review the writer process and target path. Avoid copying secrets into unexpected locations; rotate exposed secrets if the write was unauthorized.",
                        ev));
                }
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

        private void AnalyzeResponseProcessRespawns(List<SysmonProcessEvent> processes, List<Alert> alerts)
        {
            if (!config.EnableResponseFollowUpDetections ||
                !config.EnableResponseLedger ||
                String.IsNullOrWhiteSpace(config.ResponseLedgerFile) ||
                !File.Exists(config.ResponseLedgerFile))
            {
                return;
            }

            List<ResponseTerminationObservation> terminations = LoadRecentResponseTerminations();
            if (terminations.Count == 0) return;

            foreach (SysmonProcessEvent process in processes)
            {
                if (process == null || String.IsNullOrWhiteSpace(process.ProcessName)) continue;

                ResponseTerminationObservation matched = FindMatchingTermination(process, terminations);
                if (matched == null) continue;

                string key = "response-respawn|" + matched.ResponseId + "|" + process.RecordId.ToString(CultureInfo.InvariantCulture);
                if (!state.MarkEventSeen(key)) continue;

                Alert alert = Alert.FromProcessEvent(
                    "RESPONSE-PROCESS-RESPAWN",
                    "Process relaunched after Arcane response termination",
                    ClampScore(config.ResponseProcessRespawnMinimumScore),
                    "Arcane previously terminated process=" + SafeReason(matched.ProcessName) +
                        " response_id=" + SafeReason(matched.ResponseId) +
                        " trigger_rule=" + SafeReason(matched.TriggerRuleId) +
                        " and a same-named process launched again within " +
                        Math.Max(1, config.ResponseProcessRespawnWindowMinutes).ToString(CultureInfo.InvariantCulture) +
                        " minute(s). This can indicate service recovery, persistence, supervisor restart, or resilient malware behavior.",
                    "Review the parent process, service/task inventory, persistence locations, and whether termination was operator-approved. Avoid repeated automated kills until the respawn source is understood.",
                    process);
                alert.Category = "Response";
                alert.CooldownKey = "RESPONSE-PROCESS-RESPAWN|" + matched.ResponseId + "|" + process.ProcessName;
                alerts.Add(alert);
            }
        }

        private ResponseTerminationObservation FindMatchingTermination(SysmonProcessEvent process, List<ResponseTerminationObservation> terminations)
        {
            ResponseTerminationObservation best = null;
            DateTime processTime = process.TimestampUtc == DateTime.MinValue ? DateTime.UtcNow : process.TimestampUtc;
            foreach (ResponseTerminationObservation termination in terminations)
            {
                if (!process.ProcessName.Equals(termination.ProcessName, StringComparison.OrdinalIgnoreCase)) continue;
                if (process.ProcessId.ToString(CultureInfo.InvariantCulture).Equals(termination.ProcessId, StringComparison.OrdinalIgnoreCase)) continue;
                if (processTime <= termination.TimestampUtc) continue;
                if (processTime > termination.TimestampUtc.AddMinutes(Math.Max(1, config.ResponseProcessRespawnWindowMinutes))) continue;
                if (best == null || termination.TimestampUtc > best.TimestampUtc) best = termination;
            }

            return best;
        }

        private List<ResponseTerminationObservation> LoadRecentResponseTerminations()
        {
            List<ResponseTerminationObservation> result = new List<ResponseTerminationObservation>();
            DateTime cutoffUtc = DateTime.UtcNow.AddMinutes(-Math.Max(1, config.ResponseProcessRespawnWindowMinutes));
            JavaScriptSerializer serializer = new JavaScriptSerializer();

            try
            {
                foreach (string line in File.ReadAllLines(config.ResponseLedgerFile))
                {
                    ResponseTerminationObservation observation = ParseResponseTermination(serializer, line);
                    if (observation == null || observation.TimestampUtc < cutoffUtc) continue;
                    result.Add(observation);
                }
            }
            catch
            {
            }

            return result;
        }

        private static ResponseTerminationObservation ParseResponseTermination(JavaScriptSerializer serializer, string line)
        {
            if (String.IsNullOrWhiteSpace(line)) return null;

            try
            {
                Dictionary<string, object> parsed = serializer.Deserialize<Dictionary<string, object>>(line);
                if (parsed == null) return null;
                if (!ReadString(parsed, "action").Equals("TerminateProcess", StringComparison.OrdinalIgnoreCase)) return null;
                if (ReadBool(parsed, "dry_run")) return null;
                if (!String.IsNullOrWhiteSpace(ReadString(parsed, "skipped_reason"))) return null;

                DateTime timestampUtc;
                if (!TryParseUtc(ReadString(parsed, "timestamp_utc"), out timestampUtc)) return null;

                string processName = ReadString(parsed, "target_process_name");
                if (String.IsNullOrWhiteSpace(processName)) return null;

                return new ResponseTerminationObservation
                {
                    TimestampUtc = timestampUtc,
                    ResponseId = ReadString(parsed, "response_id"),
                    TriggerRuleId = ReadString(parsed, "trigger_rule_id"),
                    ProcessName = processName,
                    ProcessId = ReadString(parsed, "target_value")
                };
            }
            catch
            {
                return null;
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

        private void RecordRemoteLogon(WindowsAuditEvent ev, DateTime timestampUtc)
        {
            string principal = PrincipalFor(ev);
            List<RemoteLogonObservation> values;
            if (!recentRemoteLogonsByUser.TryGetValue(principal, out values))
            {
                values = new List<RemoteLogonObservation>();
                recentRemoteLogonsByUser[principal] = values;
            }

            RemoteLogonObservation observation = new RemoteLogonObservation();
            observation.TimestampUtc = timestampUtc;
            observation.IpAddress = ev.IpAddress ?? "";
            observation.LogonType = ev.LogonType ?? "";
            values.Add(observation);
            PruneRemoteLogons(values, timestampUtc);
        }

        private RemoteLogonObservation FindRecentRemoteLogon(string principal, DateTime timestampUtc)
        {
            List<RemoteLogonObservation> values;
            if (!recentRemoteLogonsByUser.TryGetValue(principal, out values)) return null;

            PruneRemoteLogons(values, timestampUtc);
            if (values.Count == 0) return null;
            return values[values.Count - 1];
        }

        private void PruneRemoteLogons(List<RemoteLogonObservation> values, DateTime timestampUtc)
        {
            double window = Math.Max(1, config.AuthSpecialPrivilegeRemoteCorrelationMinutes);
            for (int i = values.Count - 1; i >= 0; i--)
            {
                if ((timestampUtc - values[i].TimestampUtc).TotalMinutes > window)
                {
                    values.RemoveAt(i);
                }
            }
        }

        private bool ShouldEmitStandaloneSpecialPrivilege(string principal, DateTime timestampUtc)
        {
            string key = String.IsNullOrWhiteSpace(principal) ? "unknown" : principal;
            DateTime last;
            if (lastSpecialPrivilegeAlertByPrincipal.TryGetValue(key, out last) &&
                (timestampUtc - last).TotalMinutes < Math.Max(1, config.AuthSpecialPrivilegeRepeatDampeningMinutes))
            {
                return false;
            }

            lastSpecialPrivilegeAlertByPrincipal[key] = timestampUtc;
            return true;
        }

        private static string PrincipalFor(WindowsAuditEvent ev)
        {
            if (ev == null) return "unknown";
            if (!String.IsNullOrWhiteSpace(ev.TargetUser)) return ev.TargetUser;
            if (!String.IsNullOrWhiteSpace(ev.SubjectUser)) return ev.SubjectUser;
            return "unknown";
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

        private bool IsHighRiskFileExtension(string path)
        {
            string extension = SafeExtension(path);
            return extension.Length > 0 && config.HighRiskFileExtensions.Contains(extension);
        }

        private bool IsSensitiveFilename(string path)
        {
            string fileName = SafeFileName(path);
            return ContainsConfiguredIndicator(fileName, config.SensitiveFileNameIndicators) ||
                ContainsConfiguredIndicator(fileName, config.AgentSecretIndicatorTerms);
        }

        private bool IsSuspiciousFileWriter(SysmonFileEvent ev)
        {
            string processName = ev == null ? "" : (ev.ProcessName ?? "");
            ProcessInfo process = ev == null ? null : ev.Process;
            string commandLine = process == null ? "" : (process.CommandLine ?? "");
            string parentName = process == null ? "" : (process.ParentProcessName ?? "");
            string executablePath = process == null ? (ev == null ? "" : ev.Image) : process.ExecutablePath;

            if (config.KnownRmmProcesses.Contains(processName)) return true;
            if (config.LolbinProcesses.Contains(processName)) return true;
            if (FileSystemRules.ContainsAny(commandLine, config.SuspiciousCommandLineTerms)) return true;
            if (CommandLineRules.FindEncodedCommand(commandLine, config).Detected) return true;
            if (config.SuspiciousParentProcesses.Contains(parentName)) return true;

            bool userWritable = FileSystemRules.IsUserWritablePath(executablePath, config);
            bool unsignedProcess = process != null && process.HasExecutablePath && !process.HasSigner;
            return userWritable && unsignedProcess;
        }

        private bool IsExpectedSignedFileWriter(SysmonFileEvent ev)
        {
            if (ev == null || ev.Process == null) return false;
            ProcessInfo process = ev.Process;
            if (!config.TrustedProcesses.Contains(ev.ProcessName)) return false;
            if (!process.HasSigner || !process.HasExecutablePath) return false;
            if (FileSystemRules.IsUserWritablePath(process.ExecutablePath, config)) return false;
            if (FileSystemRules.ContainsAny(process.CommandLine, config.SuspiciousCommandLineTerms)) return false;
            if (CommandLineRules.FindEncodedCommand(process.CommandLine, config).Detected) return false;
            if (config.SuspiciousParentProcesses.Contains(process.ParentProcessName)) return false;
            return true;
        }

        private bool IsAgentFileWriter(SysmonFileEvent ev)
        {
            if (ev == null || !config.EnableAgentProfile) return false;

            string processName = ev.ProcessName ?? "";
            string parentName = ev.Process == null ? "" : (ev.Process.ParentProcessName ?? "");

            return config.AgentProcessNames.Contains(processName) ||
                config.AgentProcessNames.Contains(parentName) ||
                config.AgentChildProcessNames.Contains(processName) ||
                config.AgentPackageManagerProcesses.Contains(processName);
        }

        private bool IsAgentOutsideApprovedRoots(bool agentWriter, string target)
        {
            if (!agentWriter) return false;
            if (config.AgentWorkspaceRoots.Count == 0 && config.AgentPublishRoots.Count == 0) return false;

            return !IsUnderConfiguredRoot(target, config.AgentWorkspaceRoots) &&
                !IsUnderConfiguredRoot(target, config.AgentPublishRoots);
        }

        private static bool IsUnderConfiguredRoot(string path, HashSet<string> roots)
        {
            if (String.IsNullOrWhiteSpace(path) || roots == null || roots.Count == 0) return false;

            string normalized = NormalizePathForRootCompare(path);
            foreach (string root in roots)
            {
                string normalizedRoot = NormalizePathForRootCompare(root);
                if (!String.IsNullOrWhiteSpace(normalizedRoot) &&
                    normalized.StartsWith(normalizedRoot, StringComparison.OrdinalIgnoreCase))
                {
                    return true;
                }
            }

            return false;
        }

        private static bool IsBrowserExtensionPath(string path)
        {
            string normalized = NormalizePathText(path);
            return (normalized.IndexOf("\\google\\chrome\\", StringComparison.OrdinalIgnoreCase) >= 0 ||
                    normalized.IndexOf("\\microsoft\\edge\\", StringComparison.OrdinalIgnoreCase) >= 0) &&
                normalized.IndexOf("\\extensions\\", StringComparison.OrdinalIgnoreCase) >= 0;
        }

        private bool IsRecentExecutableFileDrop(string imagePath, DateTime timestampUtc)
        {
            string key = NormalizePathKey(imagePath);
            if (key.Length == 0) return false;

            DateTime createdUtc;
            if (!recentExecutableFileDropsByPath.TryGetValue(key, out createdUtc)) return false;

            double minutes = Math.Abs((timestampUtc - createdUtc).TotalMinutes);
            return minutes <= 30;
        }

        private void RecordRecentExecutableFileDrop(SysmonFileEvent ev)
        {
            string key = NormalizePathKey(ev == null ? "" : ev.TargetFilename);
            if (key.Length == 0) return;

            recentExecutableFileDropsByPath[key] = ev.TimestampUtc == DateTime.MinValue ? DateTime.UtcNow : ev.TimestampUtc;
        }

        private void PruneRecentExecutableFileDrops(DateTime nowUtc)
        {
            List<string> expired = new List<string>();
            foreach (KeyValuePair<string, DateTime> item in recentExecutableFileDropsByPath)
            {
                if ((nowUtc - item.Value).TotalMinutes > 30)
                {
                    expired.Add(item.Key);
                }
            }

            foreach (string key in expired)
            {
                recentExecutableFileDropsByPath.Remove(key);
            }
        }

        private static bool ContainsConfiguredIndicator(string text, HashSet<string> indicators)
        {
            if (String.IsNullOrWhiteSpace(text) || indicators == null || indicators.Count == 0) return false;

            string normalized = NormalizePathText(text);
            foreach (string indicator in indicators)
            {
                if (!String.IsNullOrWhiteSpace(indicator) &&
                    normalized.IndexOf(NormalizePathText(indicator), StringComparison.OrdinalIgnoreCase) >= 0)
                {
                    return true;
                }
            }

            return false;
        }

        private static bool ContainsConfiguredRootText(string text, HashSet<string> roots)
        {
            if (String.IsNullOrWhiteSpace(text) || roots == null || roots.Count == 0) return false;

            string normalizedText = NormalizePathText(text);
            foreach (string root in roots)
            {
                string normalizedRoot = NormalizePathForRootCompare(root);
                if (!String.IsNullOrWhiteSpace(normalizedRoot) &&
                    normalizedText.IndexOf(normalizedRoot, StringComparison.OrdinalIgnoreCase) >= 0)
                {
                    return true;
                }
            }

            return false;
        }

        private static string SafeExtension(string path)
        {
            if (String.IsNullOrWhiteSpace(path)) return "";
            try
            {
                return Path.GetExtension(path);
            }
            catch
            {
                return "";
            }
        }

        private static string SafeFileName(string path)
        {
            if (String.IsNullOrWhiteSpace(path)) return "";
            try
            {
                return Path.GetFileName(path);
            }
            catch
            {
                return path;
            }
        }

        private static string NormalizePathKey(string path)
        {
            if (String.IsNullOrWhiteSpace(path)) return "";
            try
            {
                return Path.GetFullPath(path).TrimEnd('\\').ToLowerInvariant();
            }
            catch
            {
                return NormalizePathText(path).TrimEnd('\\').ToLowerInvariant();
            }
        }

        private static string NormalizePathForRootCompare(string path)
        {
            string normalized = NormalizePathKey(path);
            return normalized.Length == 0 ? "" : normalized.TrimEnd('\\') + "\\";
        }

        private static string NormalizePathText(string path)
        {
            return path == null ? "" : path.Replace('/', '\\');
        }

        private static bool IsPowerShellCmdletizationScaffolding(string text)
        {
            if (String.IsNullOrWhiteSpace(text)) return false;

            return ContainsAny(
                text,
                "Microsoft.PowerShell.Cmdletization.MethodParameter",
                "$__cmdletization_methodParameter",
                "$__cmdletization_objectModelWrapper") &&
                ContainsAny(
                    text,
                    "MSFT_TaskTrigger",
                    "MSFT_TaskSettings",
                    "NewTriggerBy",
                    "GetScheduledTask",
                    "ScheduledTasks");
        }

        private static bool IsPowerShellReleasePackagingScaffolding(string text)
        {
            if (String.IsNullOrWhiteSpace(text)) return false;

            return ContainsAny(text, "package-release.ps1") &&
                ContainsAny(text, "CommandInvocation(Add-Type)", "ParameterBinding(Add-Type)") &&
                ContainsAny(text, "System.IO.Compression", "System.IO.Compression.FileSystem");
        }

        private static bool IsPowerShellAppInventoryEnumeration(string text)
        {
            if (String.IsNullOrWhiteSpace(text)) return false;

            bool inventoryShape =
                ContainsAny(text, "get-startapps") &&
                ContainsAny(text, "userassist") &&
                ContainsAny(text, "get-process") &&
                ContainsAny(text, "convertto-json", "converttojson");

            if (!inventoryShape) return false;

            return !ContainsAny(
                text,
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
                "iex",
                "invoke-expression",
                "frombase64string",
                "start-process",
                "new-service",
                "schtasks",
                "set-mppreference",
                "add-mppreference",
                "disableantispyware",
                "disablerealtimemonitoring");
        }

        private bool IsUserWritableText(string text)
        {
            return PersistenceTrust.ContainsConfiguredIndicator(text, config.UserWritablePathIndicators);
        }

        private bool IsUntrustedUserWritablePersistenceText(string text, PersistenceTrustResult trust)
        {
            if (!IsUserWritableText(text)) return false;
            if (trust == null || !trust.TrustedUserWritablePath) return true;

            return !PersistenceTrust.ContainsConfiguredIndicator(trust.ExecutablePath, config.UserWritablePathIndicators);
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
                !trimmed.Equals("0.0.0.0", StringComparison.OrdinalIgnoreCase) &&
                !trimmed.Equals("::", StringComparison.OrdinalIgnoreCase) &&
                !trimmed.Equals("::1", StringComparison.OrdinalIgnoreCase) &&
                !trimmed.Equals("127.0.0.1", StringComparison.OrdinalIgnoreCase) &&
                !trimmed.Equals("localhost", StringComparison.OrdinalIgnoreCase);
        }

        private static bool IsUnspecifiedRemoteAddress(string value)
        {
            if (String.IsNullOrWhiteSpace(value)) return false;
            string trimmed = value.Trim();
            return trimmed.Equals("0.0.0.0", StringComparison.OrdinalIgnoreCase) ||
                trimmed.Equals("::", StringComparison.OrdinalIgnoreCase);
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

        private static string TrustedPersistenceBody(string changeDescription, PersistenceTrustResult trust)
        {
            string context = trust.TrustedPath && trust.TrustedSigner
                ? "trusted path and signer"
                : (trust.TrustedSigner ? "trusted signer" : "trusted path");

            return "A " + changeDescription + " matched configured trusted persistence name plus " +
                context + " indicators and did not include suspicious command, untrusted user-writable path, or RMM traits.";
        }

        private static bool TryParseUtc(string value, out DateTime result)
        {
            result = DateTime.MinValue;
            if (String.IsNullOrWhiteSpace(value)) return false;

            DateTime parsed;
            if (!DateTime.TryParse(value, CultureInfo.InvariantCulture, DateTimeStyles.AdjustToUniversal, out parsed))
            {
                return false;
            }

            result = parsed.ToUniversalTime();
            return true;
        }

        private static string ReadString(Dictionary<string, object> parsed, string key)
        {
            object value;
            return parsed.TryGetValue(key, out value) && value != null ? value.ToString() : "";
        }

        private static bool ReadBool(Dictionary<string, object> parsed, string key)
        {
            object value;
            bool result;
            return parsed.TryGetValue(key, out value) && value != null && Boolean.TryParse(value.ToString(), out result) && result;
        }
    }

    internal sealed class RemoteLogonObservation
    {
        public DateTime TimestampUtc;
        public string IpAddress;
        public string LogonType;
    }

    internal sealed class ResponseTerminationObservation
    {
        public DateTime TimestampUtc;
        public string ResponseId;
        public string TriggerRuleId;
        public string ProcessName;
        public string ProcessId;
    }

    internal sealed class AgentAdminCommandFinding
    {
        public bool Detected;
        public bool Approved;
        public string Term;
        public string CommandFamily;
        public int Score;
    }

    internal sealed class AgentGuardrailFinding
    {
        public bool Detected;
        public string Term;
        public string CommandFamily;
        public int Score;
    }
}
