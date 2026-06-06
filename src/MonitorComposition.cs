namespace ArcaneEDR
{
    internal static class MonitorComposition
    {
        public static MonitorEngine Create(string baseDirectory)
        {
            MonitorConfig config = MonitorConfig.Load(baseDirectory);
            FileLogger logger = new FileLogger(config.LogDirectory, config.MaxLogFileBytes);
            IProcessEnricher processEnricher = new WmiProcessEnricher(logger);
            INetworkSnapshotCollector netstatCollector = new NetstatNetworkSnapshotCollector(logger, processEnricher);
            ISysmonEventCollector sysmonCollector = new SysmonEventCollector(config, logger, processEnricher);
            IHostTelemetryCollector hostTelemetryCollector = new CompositeHostTelemetryCollector(new IHostTelemetryCollector[]
            {
                new PowerShellEventCollector(config, logger),
                new WindowsEventCollector(config, logger),
                new PersistenceInventoryCollector(config, logger)
            });
            INetworkSnapshotCollector collector = new CompositeNetworkSnapshotCollector(netstatCollector, sysmonCollector, hostTelemetryCollector);
            DetectionState detectionState = new DetectionState();
            BaselineStore baselineStore = new BaselineStore(config, logger);
            NetworkTrafficAnalyzer analyzer = new NetworkTrafficAnalyzer(config, detectionState, baselineStore);
            ReputationCache reputationCache = new ReputationCache(config, logger);
            CustomRuleEngine customRuleEngine = new CustomRuleEngine(config, logger);
            HostTelemetryAnalyzer hostAnalyzer = new HostTelemetryAnalyzer(config, detectionState, reputationCache, customRuleEngine);
            IAlertSink alertSink = AlertSinkFactory.Create(config, logger);
            ResponseManager responseManager = new ResponseManager(config, logger);
            ConfigIntegrityMonitor integrityMonitor = new ConfigIntegrityMonitor(config, logger);
            AlertDispatcher alertDispatcher = new AlertDispatcher(config, logger, alertSink, responseManager);
            ISecretProvider secretProvider = new EnvironmentSecretProvider();
            OpenAiSecurityAnalyzer openAiAnalyzer = new OpenAiSecurityAnalyzer(config, logger, secretProvider);
            CompactLogSampler compactLogSampler = new CompactLogSampler(config);
            HealthMonitor healthMonitor = new HealthMonitor(config, logger, alertDispatcher, openAiAnalyzer, compactLogSampler);

            return new MonitorEngine(config, logger, collector, analyzer, hostAnalyzer, alertDispatcher, integrityMonitor, healthMonitor);
        }
    }
}
