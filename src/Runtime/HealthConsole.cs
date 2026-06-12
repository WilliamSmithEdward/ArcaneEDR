using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.ServiceProcess;
using System.Web.Script.Serialization;

namespace ArcaneEDR
{
    internal static class HealthConsole
    {
        public static int Run(string baseDirectory, string[] args)
        {
            bool json = HasFlag(args, "--json");
            MonitorConfig config;
            try
            {
                config = MonitorConfig.Load(baseDirectory);
            }
            catch (Exception ex)
            {
                if (json)
                {
                    Dictionary<string, object> error = new Dictionary<string, object>();
                    error["schema"] = "arcane.health.v1";
                    error["ok"] = false;
                    error["error"] = ex.Message;
                    Console.WriteLine(new JavaScriptSerializer().Serialize(error));
                }
                else
                {
                    Console.WriteLine("Health unavailable: " + ex.Message);
                }

                return 1;
            }

            string healthPath = Path.Combine(config.LogDirectory, "ArcaneServiceHealth.state");
            HealthState state = HealthState.Load(healthPath);
            string serviceState = ReadServiceState(config.ServiceName);
            DateTime nowUtc = DateTime.UtcNow;

            Dictionary<string, object> root = new Dictionary<string, object>();
            root["schema"] = "arcane.health.v1";
            root["ok"] = serviceState.Equals("Running", StringComparison.OrdinalIgnoreCase);
            root["version"] = VersionInfo.Version;
            root["product_name"] = config.ProductName;
            root["service_name"] = config.ServiceName;
            root["service_state"] = serviceState;
            root["config_path"] = config.ConfigPath;
            root["log_directory"] = config.LogDirectory;
            root["health_file"] = healthPath;
            root["last_start_utc"] = Format(state.LastStartUtc);
            root["last_clean_stop_utc"] = Format(state.LastCleanStopUtc);
            root["last_heartbeat_utc"] = Format(state.LastHeartbeatUtc);
            root["last_daily_summary_utc"] = Format(state.LastDailySummaryUtc);
            root["last_ai_analysis_utc"] = Format(state.LastAIAnalysisUtc);
            root["last_run_id"] = state.LastRunId ?? "";
            root["state_file_running"] = state.Running;
            root["poll_count"] = state.PollCount;
            root["alert_count"] = state.AlertCount;
            root["poll_failures"] = state.PollFailures;
            root["external_send_failures"] = state.ExternalSendFailures;
            root["heartbeat_age_seconds"] = state.LastHeartbeatUtc.HasValue
                ? Math.Max(0, (int)(nowUtc - state.LastHeartbeatUtc.Value).TotalSeconds)
                : -1;

            if (json)
            {
                Console.WriteLine(new JavaScriptSerializer().Serialize(root));
                return 0;
            }

            Console.WriteLine("Arcane health");
            Console.WriteLine("ServiceState=" + serviceState);
            Console.WriteLine("Version=" + VersionInfo.Version);
            Console.WriteLine("ConfigPath=" + config.ConfigPath);
            Console.WriteLine("LogDirectory=" + config.LogDirectory);
            Console.WriteLine("HealthFile=" + healthPath);
            Console.WriteLine("LastStartUtc=" + Format(state.LastStartUtc));
            Console.WriteLine("LastHeartbeatUtc=" + Format(state.LastHeartbeatUtc));
            Console.WriteLine("LastDailySummaryUtc=" + Format(state.LastDailySummaryUtc));
            Console.WriteLine("LastAIAnalysisUtc=" + Format(state.LastAIAnalysisUtc));
            Console.WriteLine("PollCount=" + state.PollCount.ToString(CultureInfo.InvariantCulture));
            Console.WriteLine("AlertCount=" + state.AlertCount.ToString(CultureInfo.InvariantCulture));
            Console.WriteLine("PollFailures=" + state.PollFailures.ToString(CultureInfo.InvariantCulture));
            Console.WriteLine("ExternalSendFailures=" + state.ExternalSendFailures.ToString(CultureInfo.InvariantCulture));
            return 0;
        }

        private static string ReadServiceState(string serviceName)
        {
            try
            {
                using (ServiceController controller = new ServiceController(serviceName))
                {
                    return controller.Status.ToString();
                }
            }
            catch
            {
                return "NotInstalledOrUnreadable";
            }
        }

        private static string Format(DateTime? value)
        {
            return UtcTimestamp.Format(value);
        }

        private static bool HasFlag(string[] args, string name)
        {
            foreach (string arg in args)
            {
                if (arg.Equals(name, StringComparison.OrdinalIgnoreCase)) return true;
            }

            return false;
        }
    }
}
