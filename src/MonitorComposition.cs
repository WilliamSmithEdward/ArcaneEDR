namespace ArcaneEDR
{
    internal static class MonitorComposition
    {
        public static MonitorEngine Create(string baseDirectory)
        {
            MonitorConfig config = MonitorConfig.Load(baseDirectory);
            FileLogger logger = new FileLogger(config.LogDirectory, config.MaxLogFileBytes);
            IProcessEnricher processEnricher = new WmiProcessEnricher(logger);
            EventLogWatermarkStore eventLogWatermarkStore = new EventLogWatermarkStore(config, logger);
            INetworkSnapshotCollector netstatCollector = config.EnableNetstatCollector
                ? (INetworkSnapshotCollector)new NetstatNetworkSnapshotCollector(logger, processEnricher)
                : null;
            ISysmonEventCollector sysmonCollector = new SysmonEventCollector(config, logger, processEnricher, eventLogWatermarkStore);
            IHostTelemetryCollector hostTelemetryCollector = new CompositeHostTelemetryCollector(new IHostTelemetryCollector[]
            {
                new PowerShellEventCollector(config, logger, processEnricher, eventLogWatermarkStore),
                new WindowsEventCollector(config, logger, eventLogWatermarkStore),
                new PersistenceInventoryCollector(config, logger)
            }, logger);
            INetworkSnapshotCollector collector = new CompositeNetworkSnapshotCollector(netstatCollector, sysmonCollector, hostTelemetryCollector, logger);
            DetectionState detectionState = new DetectionState();
            BaselineStore baselineStore = new BaselineStore(config, logger);
            RemoteEndpointEnricher remoteEndpointEnricher = new RemoteEndpointEnricher(config, logger);
            RemoteEndpointPolicyEngine remoteEndpointPolicyEngine = new RemoteEndpointPolicyEngine(config, logger);
            NetworkTrafficAnalyzer analyzer = new NetworkTrafficAnalyzer(config, detectionState, baselineStore, remoteEndpointEnricher, remoteEndpointPolicyEngine);
            ReputationCache reputationCache = new ReputationCache(config, logger);
            CustomRuleEngine customRuleEngine = new CustomRuleEngine(config, logger);
            HostTelemetryAnalyzer hostAnalyzer = new HostTelemetryAnalyzer(config, detectionState, reputationCache, customRuleEngine);
            IAlertSink alertSink = AlertSinkFactory.Create(config, logger);
            ResponseManager responseManager = new ResponseManager(config, logger);
            ConfigIntegrityMonitor integrityMonitor = new ConfigIntegrityMonitor(config, logger);
            AlertDispatcher alertDispatcher = new AlertDispatcher(config, logger, alertSink, responseManager);
            ISecretProvider secretProvider = new EnvironmentSecretProvider();
            IAiAnalysisProvider aiAnalysisProvider = AiAnalysisProviderFactory.Create(config, logger, secretProvider);
            CompactLogSampler compactLogSampler = new CompactLogSampler(config);
            HealthMonitor healthMonitor = new HealthMonitor(config, logger, alertDispatcher, aiAnalysisProvider, compactLogSampler);

            return new MonitorEngine(config, logger, collector, analyzer, hostAnalyzer, alertDispatcher, integrityMonitor, healthMonitor);
        }
    }
}
