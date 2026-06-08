using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Net;

namespace ArcaneEDR
{
    internal sealed class ResponseManager
    {
        public const string FirewallRulePrefix = "ArcaneEDR_BLOCK_";

        private readonly MonitorConfig config;
        private readonly FileLogger logger;
        private readonly object ledgerGate = new object();

        public ResponseManager(MonitorConfig config, FileLogger logger)
        {
            this.config = config;
            this.logger = logger;
        }

        public void Handle(Alert alert)
        {
            if (alert == null || config == null) return;
            if (alert.Score < config.ResponseMinimumScore) return;
            if (IsAlertOnly) return;

            bool dryRun = IsDryRunMode;
            ResponsePolicyDecision policyDecision = EvaluateActiveResponsePolicy(alert);
            if (!dryRun)
            {
                if (!policyDecision.Allowed)
                {
                    RecordResponse(alert, "ResponsePolicy", false, "rule", alert.RuleId ?? "", policyDecision.Reason, NewResponseId(), "");
                    Warn("Active response skipped by response policy rule=" + (alert.RuleId ?? "") + " reason=" + policyDecision.Reason + ".");
                    return;
                }
            }

            string dryRunPolicyReason = dryRun && !policyDecision.Allowed
                ? "active response policy would skip: " + policyDecision.Reason
                : "";

            if (WantsBlockRemote)
            {
                if (alert.ResponseRemoteAddress == null || alert.ResponseRemoteAddress.Equals(IPAddress.None))
                {
                    RecordResponse(alert, "BlockRemoteIp", dryRun, "remote_ip", "", CombineReasons(dryRunPolicyReason, "no remote address on alert"), "", "");
                }
                else if (dryRun)
                {
                    string responseId = NewResponseId();
                    string firewallRuleName = FirewallRuleName(responseId);
                    RecordResponse(alert, "BlockRemoteIp", true, "remote_ip", alert.ResponseRemoteAddress.ToString(), dryRunPolicyReason, responseId, firewallRuleName);
                    Info("Response dry-run would block remote " + alert.ResponseRemoteAddress + " firewall_rule=" + firewallRuleName + " rule=" + alert.RuleId + PolicyLogSuffix(policyDecision) + ".");
                }
                else
                {
                    if (config.EnableFirewallBlockResponse)
                    {
                        string responseId = NewResponseId();
                        string firewallRuleName = FirewallRuleName(responseId);
                        bool created = BlockRemote(alert.ResponseRemoteAddress, alert.RuleId, firewallRuleName);
                        RecordResponse(alert, "BlockRemoteIp", false, "remote_ip", alert.ResponseRemoteAddress.ToString(), created ? "" : "firewall rule create failed", responseId, firewallRuleName);
                    }
                    else
                    {
                        RecordResponse(alert, "BlockRemoteIp", false, "remote_ip", alert.ResponseRemoteAddress.ToString(), "EnableFirewallBlockResponse is false", NewResponseId(), "");
                        Warn("Firewall block response skipped because EnableFirewallBlockResponse=false rule=" + alert.RuleId + ".");
                    }
                }
            }

            if (WantsTerminateProcess)
            {
                if (alert.ResponseProcessId <= 4)
                {
                    RecordResponse(alert, "TerminateProcess", dryRun, "pid", alert.ResponseProcessId.ToString(CultureInfo.InvariantCulture), CombineReasons(dryRunPolicyReason, "no eligible process id on alert"), "", "");
                }
                else if (dryRun)
                {
                    string skippedReason = CombineReasons(dryRunPolicyReason, DryRunTerminateEligibilityReason(alert));
                    RecordResponse(alert, "TerminateProcess", true, "pid", alert.ResponseProcessId.ToString(CultureInfo.InvariantCulture), skippedReason, NewResponseId(), "");
                    Info("Response dry-run would terminate pid=" + alert.ResponseProcessId.ToString(CultureInfo.InvariantCulture) + " rule=" + alert.RuleId + PolicyLogSuffix(policyDecision) + ".");
                }
                else
                {
                    if (config.EnableProcessTerminationResponse)
                    {
                        string skippedReason;
                        bool terminated = TerminateProcess(alert.ResponseProcessId, alert.RuleId, TargetProcessName(alert, "pid"), out skippedReason);
                        RecordResponse(alert, "TerminateProcess", false, "pid", alert.ResponseProcessId.ToString(CultureInfo.InvariantCulture), terminated ? "" : skippedReason, NewResponseId(), "");
                    }
                    else
                    {
                        RecordResponse(alert, "TerminateProcess", false, "pid", alert.ResponseProcessId.ToString(CultureInfo.InvariantCulture), "EnableProcessTerminationResponse is false", NewResponseId(), "");
                        Warn("Process termination response skipped because EnableProcessTerminationResponse=false rule=" + alert.RuleId + ".");
                    }
                }
            }
        }

        private bool IsAlertOnly
        {
            get { return config.ResponseMode.Equals("AlertOnly", StringComparison.OrdinalIgnoreCase); }
        }

        private bool IsDryRunMode
        {
            get { return config.ResponseMode.StartsWith("DryRun", StringComparison.OrdinalIgnoreCase); }
        }

        private bool WantsBlockRemote
        {
            get
            {
                return config.ResponseMode.Equals("BlockRemoteIp", StringComparison.OrdinalIgnoreCase) ||
                    config.ResponseMode.Equals("BlockAndTerminate", StringComparison.OrdinalIgnoreCase) ||
                    config.ResponseMode.Equals("DryRunBlockRemoteIp", StringComparison.OrdinalIgnoreCase) ||
                    config.ResponseMode.Equals("DryRunBlockAndTerminate", StringComparison.OrdinalIgnoreCase);
            }
        }

        private bool WantsTerminateProcess
        {
            get
            {
                return config.ResponseMode.Equals("TerminateProcess", StringComparison.OrdinalIgnoreCase) ||
                    config.ResponseMode.Equals("BlockAndTerminate", StringComparison.OrdinalIgnoreCase) ||
                    config.ResponseMode.Equals("DryRunTerminateProcess", StringComparison.OrdinalIgnoreCase) ||
                    config.ResponseMode.Equals("DryRunBlockAndTerminate", StringComparison.OrdinalIgnoreCase);
            }
        }

        private ResponsePolicyDecision EvaluateActiveResponsePolicy(Alert alert)
        {
            if (!config.EnableResponsePolicy) return ResponsePolicyDecision.Allow();

            string ruleId = alert == null ? "" : (alert.RuleId ?? "");
            string category = AlertRulePolicy.AlertCategory(alert);

            if (ContainsConfigured(config.ResponseBlockedRuleIds, ruleId))
            {
                return ResponsePolicyDecision.Deny("blocked rule id: " + ruleId);
            }

            if (ContainsConfigured(config.ResponseBlockedCategories, category))
            {
                return ResponsePolicyDecision.Deny("blocked category: " + category);
            }

            bool hasAllowPolicy =
                HasConfiguredValues(config.ResponseAllowedRuleIds) ||
                HasConfiguredValues(config.ResponseAllowedCategories);

            if (!hasAllowPolicy)
            {
                return ResponsePolicyDecision.Deny("no ResponseAllowedRuleIds or ResponseAllowedCategories configured");
            }

            if (ContainsConfigured(config.ResponseAllowedRuleIds, ruleId) ||
                ContainsConfigured(config.ResponseAllowedCategories, category))
            {
                return ResponsePolicyDecision.Allow();
            }

            return ResponsePolicyDecision.Deny("rule/category not in response allow policy");
        }

        private bool BlockRemote(IPAddress address, string ruleId, string firewallRuleName)
        {
            if (address == null || address.Equals(IPAddress.None)) return false;

            try
            {
                ProcessStartInfo startInfo = new ProcessStartInfo("netsh.exe",
                    "advfirewall firewall add rule name=\"" + firewallRuleName + "\" dir=out action=block remoteip=" + address)
                {
                    CreateNoWindow = true,
                    UseShellExecute = false,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true
                };

                BoundedProcessResult result = BoundedProcessRunner.Run(startInfo, 10000);
                if (result.TimedOut)
                {
                    Error("Response block timed out for remote " + address + " firewall_rule=" + firewallRuleName + " rule=" + ruleId + ".");
                    return false;
                }

                if (!String.IsNullOrWhiteSpace(result.StandardError))
                {
                    Warn("Response block stderr: " + result.StandardError.Trim());
                }

                Info("Response block remote " + address + " firewall_rule=" + firewallRuleName + " rule=" + ruleId + " exit=" + result.ExitCode.ToString(CultureInfo.InvariantCulture));
                return result.ExitCode == 0;
            }
            catch (Exception ex)
            {
                Error("Response block failed: " + ex.Message);
            }

            return false;
        }

        private bool TerminateProcess(int processId, string ruleId, string expectedProcessName, out string skippedReason)
        {
            skippedReason = "";
            if (processId <= 4)
            {
                skippedReason = "no eligible process id on alert";
                return false;
            }

            try
            {
                using (Process process = Process.GetProcessById(processId))
                {
                    string liveName = ProcessFileName(process);
                    if (String.IsNullOrWhiteSpace(expectedProcessName))
                    {
                        skippedReason = "missing expected process name on alert";
                        Warn("Response terminate skipped for pid=" + processId.ToString(CultureInfo.InvariantCulture) + " because " + skippedReason + " rule=" + ruleId + ".");
                        return false;
                    }

                    if (!ProcessNameMatches(expectedProcessName, liveName))
                    {
                        skippedReason = "live process identity mismatch expected=" + SafeToken(expectedProcessName) + " actual=" + SafeToken(liveName);
                        Warn("Response terminate skipped for pid=" + processId.ToString(CultureInfo.InvariantCulture) + " because " + skippedReason + " rule=" + ruleId + ".");
                        return false;
                    }

                    if (IsProtectedResponseProcess(liveName))
                    {
                        skippedReason = "protected process name: " + SafeToken(liveName);
                        Warn("Response terminate skipped for pid=" + processId.ToString(CultureInfo.InvariantCulture) + " because " + skippedReason + " rule=" + ruleId + ".");
                        return false;
                    }

                    process.Kill();
                    Info("Response terminated pid=" + processId.ToString(CultureInfo.InvariantCulture) + " process=" + liveName + " rule=" + ruleId);
                    return true;
                }
            }
            catch (ArgumentException)
            {
                skippedReason = "process not found";
            }
            catch (Exception ex)
            {
                skippedReason = "process terminate failed: " + ex.Message;
                Error("Response terminate failed: " + ex.Message);
            }

            return false;
        }

        private string DryRunTerminateEligibilityReason(Alert alert)
        {
            string expectedProcessName = TargetProcessName(alert, "pid");
            if (String.IsNullOrWhiteSpace(expectedProcessName))
            {
                return "active process termination would skip: missing expected process name on alert";
            }

            if (IsProtectedResponseProcess(expectedProcessName))
            {
                return "active process termination would skip: protected process name: " + SafeToken(expectedProcessName);
            }

            return "";
        }

        private bool IsProtectedResponseProcess(string processName)
        {
            return ContainsProcessName(config.ResponseProtectedProcessNames, processName) ||
                ContainsProcessName(config.AgentProcessNames, processName) ||
                ContainsProcessName(config.AgentChildProcessNames, processName) ||
                ContainsProcessName(config.AgentPackageManagerProcesses, processName);
        }

        private void RecordResponse(Alert alert, string action, bool dryRun, string targetType, string targetValue, string skippedReason, string responseId, string firewallRuleName)
        {
            if (!config.EnableResponseLedger || String.IsNullOrWhiteSpace(config.ResponseLedgerFile)) return;

            try
            {
                lock (ledgerGate)
                {
                    string directory = Path.GetDirectoryName(config.ResponseLedgerFile);
                    if (!String.IsNullOrWhiteSpace(directory)) Directory.CreateDirectory(directory);
                    RotateIfNeeded(config.ResponseLedgerFile);
                    File.AppendAllText(config.ResponseLedgerFile, ResponseJson(alert, action, dryRun, targetType, targetValue, skippedReason, responseId, firewallRuleName) + Environment.NewLine);
                }
            }
            catch (Exception ex)
            {
                if (logger != null)
                {
                    logger.Warn("Response ledger write failed: " + ex.Message);
                }
            }
        }

        private void RotateIfNeeded(string path)
        {
            try
            {
                FileInfo file = new FileInfo(path);
                if (!file.Exists || file.Length < config.MaxLogFileBytes) return;

                string rotated = path + "." + DateTime.UtcNow.ToString("yyyyMMddHHmmss", CultureInfo.InvariantCulture) + ".old";
                File.Move(path, rotated);
            }
            catch
            {
            }
        }

        private string ResponseJson(Alert alert, string action, bool dryRun, string targetType, string targetValue, string skippedReason, string responseId, string firewallRuleName)
        {
            return "{" +
                "\"timestamp_utc\":\"" + JsonEscape(DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ", CultureInfo.InvariantCulture)) + "\"," +
                "\"response_id\":\"" + JsonEscape(responseId) + "\"," +
                "\"mode\":\"" + JsonEscape(config.ResponseMode) + "\"," +
                "\"dry_run\":" + (dryRun ? "true" : "false") + "," +
                "\"action\":\"" + JsonEscape(action) + "\"," +
                "\"trigger_rule_id\":\"" + JsonEscape(alert.RuleId) + "\"," +
                "\"trigger_title\":\"" + JsonEscape(alert.Title) + "\"," +
                "\"rule_id\":\"" + JsonEscape(alert.RuleId) + "\"," +
                "\"category\":\"" + JsonEscape(AlertRulePolicy.AlertCategory(alert)) + "\"," +
                "\"score\":" + alert.Score.ToString(CultureInfo.InvariantCulture) + "," +
                "\"severity\":\"" + JsonEscape(alert.Severity) + "\"," +
                "\"target_type\":\"" + JsonEscape(targetType) + "\"," +
                "\"target_value\":\"" + JsonEscape(targetValue) + "\"," +
                "\"target_process_name\":\"" + JsonEscape(TargetProcessName(alert, targetType)) + "\"," +
                "\"firewall_rule_name\":\"" + JsonEscape(firewallRuleName) + "\"," +
                "\"skipped_reason\":\"" + JsonEscape(skippedReason) + "\"" +
                "}";
        }

        private static string NewResponseId()
        {
            return Guid.NewGuid().ToString("N");
        }

        public static string FirewallRuleName(string responseId)
        {
            return FirewallRulePrefix + (responseId ?? "");
        }

        private static string TargetProcessName(Alert alert, string targetType)
        {
            if (alert == null || !String.Equals(targetType, "pid", StringComparison.OrdinalIgnoreCase)) return "";
            string text = (alert.EntitySummary ?? "") + " " + (alert.Body ?? "");
            return SafeToken(FieldValue(text, "process="));
        }

        private static string FieldValue(string text, string fieldName)
        {
            if (String.IsNullOrWhiteSpace(text) || String.IsNullOrWhiteSpace(fieldName)) return "";
            int index = text.IndexOf(fieldName, StringComparison.OrdinalIgnoreCase);
            if (index < 0) return "";

            int start = index + fieldName.Length;
            while (start < text.Length && Char.IsWhiteSpace(text[start])) start++;
            int end = start;
            while (end < text.Length &&
                !Char.IsWhiteSpace(text[end]) &&
                text[end] != '|' &&
                text[end] != ',' &&
                text[end] != ';')
            {
                end++;
            }

            return end > start ? text.Substring(start, end - start) : "";
        }

        private static string SafeToken(string value)
        {
            if (String.IsNullOrWhiteSpace(value)) return "";
            string result = value.Trim().Replace("\"", "").Replace("'", "");
            return result.Length <= 120 ? result : result.Substring(0, 120);
        }

        private static bool HasConfiguredValues(HashSet<string> values)
        {
            if (values == null) return false;
            foreach (string value in values)
            {
                if (!String.IsNullOrWhiteSpace(value)) return true;
            }

            return false;
        }

        private static string CombineReasons(string first, string second)
        {
            if (String.IsNullOrWhiteSpace(first)) return second ?? "";
            if (String.IsNullOrWhiteSpace(second)) return first ?? "";
            return first + "; " + second;
        }

        private static string PolicyLogSuffix(ResponsePolicyDecision decision)
        {
            if (decision == null || decision.Allowed) return " policy=allowed";
            return " policy=would_skip reason=" + SafeToken(decision.Reason);
        }

        private static bool ContainsConfigured(HashSet<string> values, string expected)
        {
            if (values == null || String.IsNullOrWhiteSpace(expected)) return false;
            foreach (string value in values)
            {
                if (!String.IsNullOrWhiteSpace(value) &&
                    value.Trim().Equals(expected, StringComparison.OrdinalIgnoreCase))
                {
                    return true;
                }
            }

            return false;
        }

        private static bool ContainsProcessName(HashSet<string> values, string processName)
        {
            if (values == null || String.IsNullOrWhiteSpace(processName)) return false;
            foreach (string value in values)
            {
                if (String.IsNullOrWhiteSpace(value)) continue;
                if (ProcessNameMatches(value, processName)) return true;
            }

            return false;
        }

        private static bool ProcessNameMatches(string expected, string actual)
        {
            string expectedName = NormalizeProcessName(expected);
            string actualName = NormalizeProcessName(actual);
            return !String.IsNullOrWhiteSpace(expectedName) &&
                !String.IsNullOrWhiteSpace(actualName) &&
                expectedName.Equals(actualName, StringComparison.OrdinalIgnoreCase);
        }

        private static string NormalizeProcessName(string value)
        {
            if (String.IsNullOrWhiteSpace(value)) return "";

            string result = value.Trim().Trim('"').Trim('\'');
            try
            {
                string fileName = Path.GetFileName(result);
                if (!String.IsNullOrWhiteSpace(fileName)) result = fileName;
            }
            catch
            {
            }

            if (result.EndsWith(".exe", StringComparison.OrdinalIgnoreCase))
            {
                result = result.Substring(0, result.Length - 4);
            }

            return result;
        }

        private static string ProcessFileName(Process process)
        {
            if (process == null) return "";

            string name = process.ProcessName ?? "";
            if (String.IsNullOrWhiteSpace(name)) return "";
            return name.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) ? name : name + ".exe";
        }

        private static string JsonEscape(string value)
        {
            if (value == null) return "";
            return value
                .Replace("\\", "\\\\")
                .Replace("\"", "\\\"")
                .Replace("\r", "\\r")
                .Replace("\n", "\\n");
        }

        private void Warn(string message)
        {
            if (logger != null)
            {
                logger.Warn(message);
            }
        }

        private void Info(string message)
        {
            if (logger != null)
            {
                logger.Info(message);
            }
        }

        private void Error(string message)
        {
            if (logger != null)
            {
                logger.Error(message);
            }
        }
    }

    internal sealed class ResponsePolicyDecision
    {
        public bool Allowed;
        public string Reason;

        public static ResponsePolicyDecision Allow()
        {
            return new ResponsePolicyDecision { Allowed = true, Reason = "" };
        }

        public static ResponsePolicyDecision Deny(string reason)
        {
            return new ResponsePolicyDecision { Allowed = false, Reason = reason ?? "" };
        }
    }
}
