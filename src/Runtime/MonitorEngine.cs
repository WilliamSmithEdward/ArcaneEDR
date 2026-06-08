using System;
using System.Collections.Generic;
using System.Threading;

namespace ArcaneEDR
{
    internal sealed class MonitorEngine
    {
        private readonly MonitorConfig config;
        private readonly FileLogger logger;
        private readonly INetworkSnapshotCollector collector;
        private readonly NetworkTrafficAnalyzer analyzer;
        private readonly HostTelemetryAnalyzer hostAnalyzer;
        private readonly AlertDispatcher alertDispatcher;
        private readonly ConfigIntegrityMonitor integrityMonitor;
        private readonly HealthMonitor healthMonitor;
        private readonly object gate = new object();
        private Timer timer;
        private bool running;
        private bool polling;
        private readonly HashSet<string> warnedStages = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        public MonitorEngine(
            MonitorConfig config,
            FileLogger logger,
            INetworkSnapshotCollector collector,
            NetworkTrafficAnalyzer analyzer,
            HostTelemetryAnalyzer hostAnalyzer,
            AlertDispatcher alertDispatcher,
            ConfigIntegrityMonitor integrityMonitor,
            HealthMonitor healthMonitor)
        {
            this.config = config;
            this.logger = logger;
            this.collector = collector;
            this.analyzer = analyzer;
            this.hostAnalyzer = hostAnalyzer;
            this.alertDispatcher = alertDispatcher;
            this.integrityMonitor = integrityMonitor;
            this.healthMonitor = healthMonitor;
        }

        public bool IsRunning
        {
            get { return running; }
        }

        public void Start()
        {
            running = true;
            logger.Info("Monitor started.");
            healthMonitor.Start();
            timer = new Timer(Poll, null, TimeSpan.Zero, TimeSpan.FromSeconds(config.PollIntervalSeconds));
        }

        public void Stop()
        {
            running = false;
            if (timer != null)
            {
                timer.Dispose();
                timer = null;
            }

            logger.Info("Monitor stopped.");
            healthMonitor.Stop();
        }

        public int RunOnce()
        {
            logger.Info("Monitor one-shot poll started.");
            try
            {
                List<Alert> alerts = CollectAlerts(DateTime.UtcNow);
                alertDispatcher.Dispatch(alerts);
                logger.Info("Monitor one-shot poll completed alerts=" + alerts.Count.ToString(System.Globalization.CultureInfo.InvariantCulture) + ".");
                return 0;
            }
            catch (Exception ex)
            {
                logger.Error("One-shot poll failed: " + ex);
                return 1;
            }
        }

        private void Poll(object state)
        {
            lock (gate)
            {
                if (polling) return;
                polling = true;
            }

            try
            {
                List<Alert> alerts = CollectAlerts(DateTime.UtcNow);
                alertDispatcher.Dispatch(alerts);
                healthMonitor.RecordPoll(alerts);
            }
            catch (Exception ex)
            {
                logger.Error("Poll failed: " + ex);
                healthMonitor.RecordPollFailure();
            }
            finally
            {
                lock (gate)
                {
                    polling = false;
                }
            }
        }

        private List<Alert> CollectAlerts(DateTime timestampUtc)
        {
            NetworkSnapshot snapshot = CaptureSnapshot();
            List<Alert> alerts = new List<Alert>();
            AddRange(alerts, AnalyzeNetwork(snapshot, timestampUtc));
            AddRange(alerts, AnalyzeHost(snapshot, timestampUtc));
            AddRange(alerts, CheckIntegrity());
            return alerts;
        }

        private NetworkSnapshot CaptureSnapshot()
        {
            try
            {
                NetworkSnapshot snapshot = collector == null ? null : collector.Capture();
                return snapshot ?? EmptySnapshot();
            }
            catch (Exception ex)
            {
                WarnStage("collection", "Telemetry collection failed; continuing this poll with empty telemetry: " + ex.Message);
                return EmptySnapshot();
            }
        }

        private List<Alert> AnalyzeNetwork(NetworkSnapshot snapshot, DateTime timestampUtc)
        {
            try
            {
                return analyzer == null ? new List<Alert>() : analyzer.Analyze(snapshot ?? EmptySnapshot(), timestampUtc);
            }
            catch (Exception ex)
            {
                WarnStage("network-analysis", "Network analysis failed; continuing this poll with remaining checks: " + ex.Message);
                return new List<Alert>();
            }
        }

        private List<Alert> AnalyzeHost(NetworkSnapshot snapshot, DateTime timestampUtc)
        {
            try
            {
                return hostAnalyzer == null ? new List<Alert>() : hostAnalyzer.Analyze(snapshot ?? EmptySnapshot(), timestampUtc);
            }
            catch (Exception ex)
            {
                WarnStage("host-analysis", "Host analysis failed; continuing this poll with remaining checks: " + ex.Message);
                return new List<Alert>();
            }
        }

        private List<Alert> CheckIntegrity()
        {
            try
            {
                return integrityMonitor == null ? new List<Alert>() : integrityMonitor.Check();
            }
            catch (Exception ex)
            {
                WarnStage("integrity-check", "Integrity check failed; continuing this poll: " + ex.Message);
                return new List<Alert>();
            }
        }

        private void WarnStage(string stage, string message)
        {
            if (logger == null) return;

            string key = String.IsNullOrWhiteSpace(stage) ? "unknown" : stage;
            if (warnedStages.Contains(key)) return;
            warnedStages.Add(key);
            logger.Warn(message);
        }

        private static void AddRange(List<Alert> target, List<Alert> source)
        {
            if (target == null || source == null) return;
            target.AddRange(source);
        }

        private static NetworkSnapshot EmptySnapshot()
        {
            return new NetworkSnapshot(
                new List<NetworkEndpoint>(),
                new List<DnsQueryEvent>(),
                new List<SysmonProcessEvent>(),
                new List<SysmonFileEvent>(),
                new HostTelemetry());
        }
    }
}
