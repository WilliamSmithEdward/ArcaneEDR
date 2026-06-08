using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Web.Script.Serialization;

namespace ArcaneEDR
{
    internal static class ResponseFirewallConsole
    {
        public static int Run(string baseDirectory, string[] args)
        {
            MonitorConfig config = MonitorConfig.Load(baseDirectory);
            string action = args != null && args.Length > 1 ? args[1] : "list";

            if (action.Equals("list", StringComparison.OrdinalIgnoreCase))
            {
                return List(config);
            }

            if (action.Equals("remove", StringComparison.OrdinalIgnoreCase))
            {
                string target = args != null && args.Length > 2 ? args[2] : "";
                return RemoveOne(target);
            }

            if (action.Equals("remove-all", StringComparison.OrdinalIgnoreCase))
            {
                return RemoveAll();
            }

            PrintUsage();
            return 1;
        }

        private static int List(MonitorConfig config)
        {
            Console.WriteLine("Arcane firewall block prefix: " + ResponseManager.FirewallRulePrefix);
            Console.WriteLine("Response ledger: " + config.ResponseLedgerFile);
            if (String.IsNullOrWhiteSpace(config.ResponseLedgerFile) || !File.Exists(config.ResponseLedgerFile))
            {
                Console.WriteLine("No response ledger found.");
                return 0;
            }

            int count = 0;
            foreach (ResponseFirewallRecord record in LoadRecords(config.ResponseLedgerFile))
            {
                if (String.IsNullOrWhiteSpace(record.FirewallRuleName)) continue;
                if (!record.FirewallRuleName.StartsWith(ResponseManager.FirewallRulePrefix, StringComparison.OrdinalIgnoreCase)) continue;

                count++;
                Console.WriteLine(record.TimestampUtc +
                    " rule_name=" + record.FirewallRuleName +
                    " response_id=" + record.ResponseId +
                    " dry_run=" + record.DryRun +
                    " target=" + record.TargetValue +
                    " trigger=" + record.TriggerRuleId +
                    " score=" + record.Score.ToString(CultureInfo.InvariantCulture) +
                    " skipped_reason=" + record.SkippedReason);
            }

            if (count == 0)
            {
                Console.WriteLine("No Arcane firewall block records found.");
            }

            return 0;
        }

        private static int RemoveOne(string target)
        {
            string ruleName = NormalizeRuleName(target);
            if (String.IsNullOrWhiteSpace(ruleName))
            {
                Console.Error.WriteLine("Provide a 32-hex Arcane response ID or ArcaneEDR_BLOCK_<response-id> firewall rule name.");
                PrintUsage();
                return 1;
            }

            return DeleteRule(ruleName);
        }

        private static int RemoveAll()
        {
            ProcessStartInfo startInfo = new ProcessStartInfo("powershell.exe",
                "-NoProfile -ExecutionPolicy Bypass -Command \"Get-NetFirewallRule -DisplayName '" +
                ResponseManager.FirewallRulePrefix +
                "*' | Remove-NetFirewallRule\"")
            {
                CreateNoWindow = true,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true
            };

            return RunProcess(startInfo, "Removed all Arcane firewall block rules with prefix " + ResponseManager.FirewallRulePrefix + ".");
        }

        private static int DeleteRule(string ruleName)
        {
            ProcessStartInfo startInfo = new ProcessStartInfo("netsh.exe",
                "advfirewall firewall delete rule name=\"" + ruleName + "\"")
            {
                CreateNoWindow = true,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true
            };

            return RunProcess(startInfo, "Removed Arcane firewall block rule: " + ruleName);
        }

        private static int RunProcess(ProcessStartInfo startInfo, string successMessage)
        {
            try
            {
                BoundedProcessResult result = BoundedProcessRunner.Run(startInfo, 15000);
                if (!String.IsNullOrWhiteSpace(result.StandardOutput))
                {
                    Console.WriteLine(result.StandardOutput.Trim());
                }

                if (!String.IsNullOrWhiteSpace(result.StandardError))
                {
                    Console.Error.WriteLine(result.StandardError.Trim());
                }

                if (result.TimedOut)
                {
                    Console.Error.WriteLine("Firewall rollback command timed out.");
                    return 1;
                }

                if (result.ExitCode == 0)
                {
                    Console.WriteLine(successMessage);
                }

                return result.ExitCode == 0 ? 0 : (result.ExitCode < 0 ? 1 : result.ExitCode);
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine("Firewall rollback command failed: " + ex.Message);
                return 1;
            }
        }

        private static string NormalizeRuleName(string target)
        {
            if (String.IsNullOrWhiteSpace(target)) return "";
            string value = TrimOuterQuotes(target.Trim());
            if (value.StartsWith(ResponseManager.FirewallRulePrefix, StringComparison.OrdinalIgnoreCase))
            {
                string suffix = value.Substring(ResponseManager.FirewallRulePrefix.Length).Replace("-", "");
                return IsHex32(suffix) ? ResponseManager.FirewallRuleName(suffix) : "";
            }

            string compact = value.Replace("-", "");
            if (IsHex32(compact))
            {
                return ResponseManager.FirewallRuleName(compact);
            }

            return "";
        }

        private static string TrimOuterQuotes(string value)
        {
            if (String.IsNullOrWhiteSpace(value)) return "";
            string result = value.Trim();
            if (result.Length >= 2 &&
                ((result[0] == '"' && result[result.Length - 1] == '"') ||
                 (result[0] == '\'' && result[result.Length - 1] == '\'')))
            {
                return result.Substring(1, result.Length - 2).Trim();
            }

            return result;
        }

        private static bool IsHex32(string value)
        {
            if (String.IsNullOrWhiteSpace(value) || value.Length != 32) return false;
            for (int i = 0; i < value.Length; i++)
            {
                char ch = value[i];
                bool hex =
                    (ch >= '0' && ch <= '9') ||
                    (ch >= 'a' && ch <= 'f') ||
                    (ch >= 'A' && ch <= 'F');
                if (!hex) return false;
            }

            return true;
        }

        private static List<ResponseFirewallRecord> LoadRecords(string path)
        {
            List<ResponseFirewallRecord> records = new List<ResponseFirewallRecord>();
            JavaScriptSerializer serializer = new JavaScriptSerializer();
            foreach (string line in File.ReadAllLines(path))
            {
                ResponseFirewallRecord record = ParseRecord(serializer, line);
                if (record != null) records.Add(record);
            }

            return records;
        }

        private static ResponseFirewallRecord ParseRecord(JavaScriptSerializer serializer, string line)
        {
            if (String.IsNullOrWhiteSpace(line)) return null;

            try
            {
                Dictionary<string, object> parsed = serializer.Deserialize<Dictionary<string, object>>(line);
                if (parsed == null) return null;
                if (!ReadString(parsed, "action").Equals("BlockRemoteIp", StringComparison.OrdinalIgnoreCase)) return null;

                return new ResponseFirewallRecord
                {
                    TimestampUtc = ReadString(parsed, "timestamp_utc"),
                    ResponseId = ReadString(parsed, "response_id"),
                    FirewallRuleName = ReadString(parsed, "firewall_rule_name"),
                    DryRun = ReadBool(parsed, "dry_run"),
                    TriggerRuleId = ReadString(parsed, "trigger_rule_id"),
                    TargetValue = ReadString(parsed, "target_value"),
                    Score = ReadInt(parsed, "score"),
                    SkippedReason = ReadString(parsed, "skipped_reason")
                };
            }
            catch
            {
                return null;
            }
        }

        private static string ReadString(Dictionary<string, object> parsed, string key)
        {
            object value;
            return parsed.TryGetValue(key, out value) && value != null ? value.ToString() : "";
        }

        private static int ReadInt(Dictionary<string, object> parsed, string key)
        {
            object value;
            int result;
            return parsed.TryGetValue(key, out value) && value != null && Int32.TryParse(value.ToString(), out result) ? result : 0;
        }

        private static bool ReadBool(Dictionary<string, object> parsed, string key)
        {
            object value;
            bool result;
            return parsed.TryGetValue(key, out value) && value != null && Boolean.TryParse(value.ToString(), out result) && result;
        }

        private static void PrintUsage()
        {
            Console.WriteLine("Usage:");
            Console.WriteLine("  ArcaneEDR.exe --response-firewall list");
            Console.WriteLine("  ArcaneEDR.exe --response-firewall remove <response-id-or-ArcaneEDR_BLOCK_guid>");
            Console.WriteLine("  ArcaneEDR.exe --response-firewall remove-all");
        }
    }

    internal sealed class ResponseFirewallRecord
    {
        public string TimestampUtc;
        public string ResponseId;
        public string FirewallRuleName;
        public bool DryRun;
        public string TriggerRuleId;
        public string TargetValue;
        public int Score;
        public string SkippedReason;
    }
}
