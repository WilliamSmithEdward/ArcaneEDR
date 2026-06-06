using System;
using System.Diagnostics;
using System.Globalization;
using System.Net;

namespace ArcaneEDR
{
    internal sealed class ResponseManager
    {
        private readonly MonitorConfig config;
        private readonly FileLogger logger;

        public ResponseManager(MonitorConfig config, FileLogger logger)
        {
            this.config = config;
            this.logger = logger;
        }

        public void Handle(Alert alert)
        {
            if (alert.Score < config.ResponseMinimumScore) return;
            if (config.ResponseMode.Equals("AlertOnly", StringComparison.OrdinalIgnoreCase)) return;

            if (config.ResponseMode.Equals("BlockRemoteIp", StringComparison.OrdinalIgnoreCase) ||
                config.ResponseMode.Equals("BlockAndTerminate", StringComparison.OrdinalIgnoreCase))
            {
                BlockRemote(alert.ResponseRemoteAddress, alert.RuleId);
            }

            if (config.ResponseMode.Equals("TerminateProcess", StringComparison.OrdinalIgnoreCase) ||
                config.ResponseMode.Equals("BlockAndTerminate", StringComparison.OrdinalIgnoreCase))
            {
                TerminateProcess(alert.ResponseProcessId, alert.RuleId);
            }
        }

        private void BlockRemote(IPAddress address, string ruleId)
        {
            if (address == null || address.Equals(IPAddress.None)) return;

            try
            {
                string name = config.ServiceName + " Block " + ruleId + " " + address;
                ProcessStartInfo startInfo = new ProcessStartInfo("netsh.exe",
                    "advfirewall firewall add rule name=\"" + name + "\" dir=out action=block remoteip=" + address)
                {
                    CreateNoWindow = true,
                    UseShellExecute = false,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true
                };

                using (Process process = Process.Start(startInfo))
                {
                    process.WaitForExit(10000);
                    logger.Info("Response block remote " + address + " exit=" + process.ExitCode.ToString(CultureInfo.InvariantCulture));
                }
            }
            catch (Exception ex)
            {
                logger.Error("Response block failed: " + ex.Message);
            }
        }

        private void TerminateProcess(int processId, string ruleId)
        {
            if (processId <= 4) return;

            try
            {
                Process process = Process.GetProcessById(processId);
                process.Kill();
                logger.Info("Response terminated pid=" + processId.ToString(CultureInfo.InvariantCulture) + " rule=" + ruleId);
            }
            catch (Exception ex)
            {
                logger.Error("Response terminate failed: " + ex.Message);
            }
        }
    }
}
