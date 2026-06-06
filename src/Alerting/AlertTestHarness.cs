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

        public static void SendOpenAiAnalysisTest(string baseDirectory)
        {
            MonitorConfig config = MonitorConfig.Load(baseDirectory);
            FileLogger logger = new FileLogger(config.LogDirectory, config.MaxLogFileBytes);
            IAlertSink alertSink = AlertSinkFactory.Create(config, logger);
            ResponseManager responseManager = new ResponseManager(config, logger);
            AlertDispatcher dispatcher = new AlertDispatcher(config, logger, alertSink, responseManager);
            ISecretProvider secretProvider = new EnvironmentSecretProvider();
            OpenAiSecurityAnalyzer openAiAnalyzer = new OpenAiSecurityAnalyzer(config, logger, secretProvider);
            CompactLogSampler sampler = new CompactLogSampler(config);
            HealthMonitor healthMonitor = new HealthMonitor(config, logger, dispatcher, openAiAnalyzer, sampler);
            healthMonitor.ForceOpenAiAnalysis();
        }

        public static void PreviewOpenAiPayload(string baseDirectory)
        {
            MonitorConfig config = MonitorConfig.Load(baseDirectory);
            CompactLogSampler sampler = new CompactLogSampler(config);
            HealthState state = HealthState.Load(Path.Combine(config.LogDirectory, "ArcaneServiceHealth.state"));
            Console.WriteLine(sampler.BuildPayload(state));
        }
    }
}
