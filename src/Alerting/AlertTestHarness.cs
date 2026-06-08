using System.Collections.Generic;
using System;
using System.IO;

namespace ArcaneEDR
{
    internal static class AlertTestHarness
    {
        public static void SendTestAlert(string baseDirectory)
        {
            SendTestAlert(baseDirectory, new string[0]);
        }

        public static void SendTestAlert(string baseDirectory, string[] args)
        {
            MonitorConfig config = MonitorConfig.Load(baseDirectory);
            FileLogger logger = new FileLogger(config.LogDirectory, config.MaxLogFileBytes);
            IAlertSink alertSink = AlertSinkFactory.Create(config, logger);
            ResponseManager responseManager = new ResponseManager(config, logger);
            AlertDispatcher dispatcher = new AlertDispatcher(config, logger, alertSink, responseManager);

            int count = ParseCount(args, 1);
            List<Alert> alerts = new List<Alert>();
            for (int index = 0; index < count; index++)
            {
                string suffix = count == 1 ? "" : " " + (index + 1).ToString(System.Globalization.CultureInfo.InvariantCulture) + " of " + count.ToString(System.Globalization.CultureInfo.InvariantCulture);
                alerts.Add(Alert.Create(
                    "TEST-ALERT-DELIVERY",
                    "Alert delivery test" + suffix,
                    100,
                    "This is a manual test alert from " + config.ProductName + ".",
                    "No action required if you intentionally ran the test.",
                    "test-alert|delivery|" + index.ToString(System.Globalization.CultureInfo.InvariantCulture)));
            }

            dispatcher.Dispatch(alerts);
        }

        public static void SendHealthTest(string baseDirectory)
        {
            MonitorConfig config = MonitorConfig.Load(baseDirectory);
            FileLogger logger = new FileLogger(config.LogDirectory, config.MaxLogFileBytes);
            IAlertSink alertSink = AlertSinkFactory.Create(config, logger);
            ResponseManager responseManager = new ResponseManager(config, logger);
            AlertDispatcher dispatcher = new AlertDispatcher(config, logger, alertSink, responseManager);

            dispatcher.SendExternal(Alert.SystemAlert(
                "SERVICE-HEALTH-TEST",
                "Service health notification test",
                100,
                "This is a manual test of service health email delivery.",
                "No action required if you intentionally ran the test.",
                "service=" + config.ServiceName));
        }

        public static void SendDailyReportTest(string baseDirectory)
        {
            MonitorConfig config = MonitorConfig.Load(baseDirectory);
            FileLogger logger = new FileLogger(config.LogDirectory, config.MaxLogFileBytes);
            IAlertSink alertSink = AlertSinkFactory.Create(config, logger);
            ResponseManager responseManager = new ResponseManager(config, logger);
            AlertDispatcher dispatcher = new AlertDispatcher(config, logger, alertSink, responseManager);
            ISecretProvider secretProvider = new EnvironmentSecretProvider();
            IAiAnalysisProvider aiAnalysisProvider = AiAnalysisProviderFactory.Create(config, logger, secretProvider);

            HealthState state = HealthState.Load(Path.Combine(config.LogDirectory, "ArcaneServiceHealth.state"));
            DateTime now = DateTime.UtcNow;
            DailyReportBuilder reportBuilder = new DailyReportBuilder(
                config,
                state,
                "daily-report-test",
                now,
                0,
                0,
                0);
            DailyReportSnapshot snapshot = reportBuilder.BuildSnapshot(now);
            AiAnalysisResult dailyAiResult = null;
            string dailyAiStatus = "disabled";

            if (config.EnableAIAnalysis && config.EnableDailySummaryAIAnalysis)
            {
                dailyAiStatus = "not_configured";
                if (aiAnalysisProvider.IsConfigured)
                {
                    string payload = reportBuilder.BuildAiPayload(snapshot);
                    dailyAiResult = aiAnalysisProvider.AnalyzeDailyReport(payload);
                    dailyAiStatus = "completed";
                }
            }

            string body = reportBuilder.BuildReport(snapshot, dailyAiResult, dailyAiStatus);
            string archiveJson = reportBuilder.BuildArchiveJson(snapshot, dailyAiResult, dailyAiStatus);
            if (config.DailyReportDestinationEnabled("LocalArchive"))
            {
                DailyReportArchive archive = new DailyReportArchive(config, logger);
                archive.Save(snapshot, body, archiveJson);
            }

            if (config.DailyReportDestinationEnabled("ReportWebhook"))
            {
                DailyReportHttpSink reportSink = new DailyReportHttpSink(config, logger, secretProvider);
                if (reportSink.IsConfigured)
                {
                    try
                    {
                        reportSink.Send(snapshot, archiveJson);
                    }
                    catch (Exception ex)
                    {
                        logger.Error("Daily report test webhook delivery failed: " + ex.Message);
                    }
                }
                else
                {
                    logger.Warn("Daily report test webhook skipped: " + reportSink.MissingConfigurationReason);
                }
            }

            if (config.DailyReportDestinationEnabled("ExternalAlertSinks"))
            {
                dispatcher.SendExternal(Alert.SystemAlert(
                    "SERVICE-DAILY-SUMMARY",
                    "Daily Arcane EDR report test",
                    config.DailySummaryScore,
                    body,
                    "No action required if you intentionally ran the daily report test.",
                    "service=" + config.ServiceName));
            }
            else
            {
                logger.Info("Daily report test external delivery skipped by DailyReportDestinations.");
            }
        }

        public static int PreviewDailyReport(string baseDirectory, string[] args)
        {
            bool json = HasArg(args, "--json");
            bool archive = HasArg(args, "--archive");

            MonitorConfig config = MonitorConfig.Load(baseDirectory);
            HealthState state = HealthState.Load(Path.Combine(config.LogDirectory, "ArcaneServiceHealth.state"));
            DateTime now = DateTime.UtcNow;
            DailyReportBuilder reportBuilder = new DailyReportBuilder(
                config,
                state,
                "daily-report-preview",
                now,
                0,
                0,
                0);
            DailyReportSnapshot snapshot = reportBuilder.BuildSnapshot(now);
            string aiStatus = "disabled: preview mode";
            string body = reportBuilder.BuildReport(snapshot, null, aiStatus);
            string archiveJson = reportBuilder.BuildArchiveJson(snapshot, null, aiStatus);

            if (archive)
            {
                DailyReportArchive reportArchive = new DailyReportArchive(config, null);
                reportArchive.Save(snapshot, body, archiveJson);
            }

            Console.WriteLine(json ? archiveJson : body);
            return 0;
        }

        public static void SendAiAnalysisTest(string baseDirectory)
        {
            MonitorConfig config = MonitorConfig.Load(baseDirectory);
            FileLogger logger = new FileLogger(config.LogDirectory, config.MaxLogFileBytes);
            IAlertSink alertSink = AlertSinkFactory.Create(config, logger);
            ResponseManager responseManager = new ResponseManager(config, logger);
            AlertDispatcher dispatcher = new AlertDispatcher(config, logger, alertSink, responseManager);
            ISecretProvider secretProvider = new EnvironmentSecretProvider();
            IAiAnalysisProvider aiAnalysisProvider = AiAnalysisProviderFactory.Create(config, logger, secretProvider);
            CompactLogSampler sampler = new CompactLogSampler(config);
            HealthMonitor healthMonitor = new HealthMonitor(config, logger, dispatcher, aiAnalysisProvider, sampler);
            healthMonitor.ForceAiAnalysis();
        }

        public static void PreviewAiPayload(string baseDirectory)
        {
            MonitorConfig config = MonitorConfig.Load(baseDirectory);
            CompactLogSampler sampler = new CompactLogSampler(config);
            HealthState state = HealthState.Load(Path.Combine(config.LogDirectory, "ArcaneServiceHealth.state"));
            Console.WriteLine(sampler.BuildPayload(state));
        }

        private static bool HasArg(string[] args, string name)
        {
            if (args == null || String.IsNullOrWhiteSpace(name)) return false;
            foreach (string arg in args)
            {
                if (arg != null && arg.Equals(name, StringComparison.OrdinalIgnoreCase))
                {
                    return true;
                }
            }

            return false;
        }

        private static int ParseCount(string[] args, int fallback)
        {
            if (args == null) return fallback;
            for (int index = 0; index < args.Length - 1; index++)
            {
                if (args[index] != null && args[index].Equals("--count", StringComparison.OrdinalIgnoreCase))
                {
                    int parsed;
                    if (Int32.TryParse(args[index + 1], out parsed) && parsed > 0)
                    {
                        return Math.Min(parsed, 20);
                    }
                }
            }

            return fallback;
        }
    }
}
