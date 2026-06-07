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
            NetworkSnapshot snapshot = collector.Capture();
            List<Alert> alerts = analyzer.Analyze(snapshot, timestampUtc);
            alerts.AddRange(hostAnalyzer.Analyze(snapshot, timestampUtc));
            alerts.AddRange(integrityMonitor.Check());
            return alerts;
        }
    }
}
