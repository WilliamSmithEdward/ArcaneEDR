using System.Collections.Generic;
using System;
using System.IO;

namespace ArcaneEDR
{
    internal static class AlertTestHarness
    {
        public static void SendTestAlert(string baseDirectory)
        {
            MonitorConfig config = MonitorConfig.Load(baseDirectory);
            FileLogger logger = new FileLogger(config.LogDirectory, config.MaxLogFileBytes);
            IAlertSink alertSink = AlertSinkFactory.Create(config, logger);
            ResponseManager responseManager = new ResponseManager(config, logger);
            AlertDispatcher dispatcher = new AlertDispatcher(config, logger, alertSink, responseManager);

            Alert alert = Alert.Create(
                "TEST-ALERT-DELIVERY",
                "Alert delivery test",
                100,
                "This is a manual test alert from " + config.ProductName + ".",
                "No action required if you intentionally ran the test.",
                "test-alert|delivery");

            dispatcher.Dispatch(new List<Alert> { alert });
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
            OpenAiAnalysisResult dailyAiResult = null;
            string dailyAiStatus = "disabled";

            if (config.EnableOpenAiLogAnalysis && config.EnableDailySummaryOpenAiAnalysis)
            {
                dailyAiStatus = "not_configured";
                if (aiAnalysisProvider.IsConfigured)
                {
                    string payload = reportBuilder.BuildOpenAiPayload(snapshot);
                    dailyAiResult = aiAnalysisProvider.AnalyzeDailyReport(payload);
                    dailyAiStatus = "completed";
                }
            }

            string body = reportBuilder.BuildReport(snapshot, dailyAiResult, dailyAiStatus);
            if (config.DailyReportDestinationEnabled("LocalArchive"))
            {
                DailyReportArchive archive = new DailyReportArchive(config, logger);
                archive.Save(snapshot, body, reportBuilder.BuildArchiveJson(snapshot, dailyAiResult, dailyAiStatus));
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

        public static void SendOpenAiAnalysisTest(string baseDirectory)
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
            healthMonitor.ForceOpenAiAnalysis();
        }

        public static void PreviewOpenAiPayload(string baseDirectory)
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
    }
}
