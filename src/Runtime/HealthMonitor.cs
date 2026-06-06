using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;

namespace ArcaneEDR
{
    internal sealed class HealthMonitor
    {
        private readonly MonitorConfig config;
        private readonly FileLogger logger;
        private readonly AlertDispatcher dispatcher;
        private readonly OpenAiSecurityAnalyzer openAiAnalyzer;
        private readonly CompactLogSampler compactLogSampler;
        private readonly string statePath;
        private readonly string runId;
        private HealthState state;
        private DateTime startedUtc;
        private DateTime lastHeartbeatPersistUtc;
        private long currentRunPolls;
        private long currentRunAlerts;
        private long currentRunPollFailures;

        public HealthMonitor(
            MonitorConfig config,
            FileLogger logger,
            AlertDispatcher dispatcher,
            OpenAiSecurityAnalyzer openAiAnalyzer,
            CompactLogSampler compactLogSampler)
        {
            this.config = config;
            this.logger = logger;
            this.dispatcher = dispatcher;
            this.openAiAnalyzer = openAiAnalyzer;
            this.compactLogSampler = compactLogSampler;
            statePath = Path.Combine(config.LogDirectory, "ArcaneServiceHealth.state");
            runId = Guid.NewGuid().ToString("N");
        }

        public void Start()
        {
            startedUtc = DateTime.UtcNow;
            state = HealthState.Load(statePath);
            bool recovered = config.NotifyOnCrashRecovery && state.Running;
            DateTime? previousHeartbeat = state.LastHeartbeatUtc;
            DateTime? previousStart = state.LastStartUtc;

            state.LastStartUtc = startedUtc;
            state.LastHeartbeatUtc = startedUtc;
            state.LastRunId = runId;
            state.Running = true;
            Save();

            if (config.NotifyOnServiceStart)
            {
                string body = config.ProductName + " started at " + Format(startedUtc) +
                    Environment.NewLine + "RunId: " + runId +
                    Environment.NewLine + "Config: " + config.ConfigPath +
                    Environment.NewLine + "LogDirectory: " + config.LogDirectory;

                if (recovered)
                {
                    body += Environment.NewLine + Environment.NewLine +
                        "Previous run did not record a clean stop." +
                        Environment.NewLine + "PreviousStartUtc: " + Format(previousStart) +
                        Environment.NewLine + "PreviousHeartbeatUtc: " + Format(previousHeartbeat);
                }

                dispatcher.SendExternal(Alert.SystemAlert(
                    recovered ? "SERVICE-RECOVERED-AFTER-UNCLEAN-STOP" : "SERVICE-STARTED",
                    recovered ? "Service recovered after unclean stop" : "Service started",
                    recovered ? 80 : 60,
                    body,
                    recovered ? "Review recent host activity and service logs for the cause of the crash or forced stop." : "No action required.",
                    ServiceEntity()));
            }
        }

        public void Stop()
        {
            if (state == null) state = HealthState.Load(statePath);
            state.LastCleanStopUtc = DateTime.UtcNow;
            state.LastHeartbeatUtc = DateTime.UtcNow;
            state.Running = false;
            Save();

            if (config.NotifyOnServiceStop)
            {
                dispatcher.SendExternal(Alert.SystemAlert(
                    "SERVICE-STOPPED",
                    "Service stopped cleanly",
                    50,
                    config.ProductName + " stopped cleanly at " + Format(DateTime.UtcNow) + ".",
                    "No action required if this was expected.",
                    ServiceEntity()));
            }
        }

        public void RecordPoll(List<Alert> alerts)
        {
            currentRunPolls++;
            currentRunAlerts += alerts == null ? 0 : alerts.Count;
            state.PollCount++;
            state.AlertCount += alerts == null ? 0 : alerts.Count;
            HeartbeatIfNeeded();
            SendOpenAiAnalysisIfDue();
            SendDailySummaryIfDue();
        }

        public void RecordPollFailure()
        {
            currentRunPollFailures++;
            state.PollFailures++;
            HeartbeatIfNeeded();
        }

        private void HeartbeatIfNeeded()
        {
            DateTime now = DateTime.UtcNow;
            if ((now - lastHeartbeatPersistUtc).TotalSeconds < config.HealthHeartbeatSeconds) return;

            state.LastHeartbeatUtc = now;
            lastHeartbeatPersistUtc = now;
            Save();
        }

        private void SendDailySummaryIfDue()
        {
            if (!config.EnableDailySummary) return;

            DateTime now = DateTime.UtcNow;
            if (!DailySummarySchedule.IsDue(config, now, state.LastDailySummaryUtc))
            {
                return;
            }

            state.LastDailySummaryUtc = now;
            Save();

            string body =
                "Daily summary for " + config.ProductName + Environment.NewLine +
                "UTC: " + Format(now) + Environment.NewLine +
                "ScheduledLocalTime: " + DailySummarySchedule.Describe(config) + Environment.NewLine +
                "RunId: " + runId + Environment.NewLine +
                "CurrentRunUptimeHours: " + (now - startedUtc).TotalHours.ToString("0.00", CultureInfo.InvariantCulture) + Environment.NewLine +
                "CurrentRunPolls: " + currentRunPolls.ToString(CultureInfo.InvariantCulture) + Environment.NewLine +
                "CurrentRunAlerts: " + currentRunAlerts.ToString(CultureInfo.InvariantCulture) + Environment.NewLine +
                "CurrentRunPollFailures: " + currentRunPollFailures.ToString(CultureInfo.InvariantCulture) + Environment.NewLine +
                "TotalPolls: " + state.PollCount.ToString(CultureInfo.InvariantCulture) + Environment.NewLine +
                "TotalAlerts: " + state.AlertCount.ToString(CultureInfo.InvariantCulture) + Environment.NewLine +
                "TotalPollFailures: " + state.PollFailures.ToString(CultureInfo.InvariantCulture) + Environment.NewLine +
                "LastCleanStopUtc: " + Format(state.LastCleanStopUtc) + Environment.NewLine +
                "BaselineLearningMode: " + config.BaselineLearningMode;

            dispatcher.SendExternal(Alert.SystemAlert(
                "SERVICE-DAILY-SUMMARY",
                "Daily Arcane EDR monitor summary",
                config.DailySummaryScore,
                body,
                "Review alert volume, failures, and whether baseline learning should remain enabled.",
                ServiceEntity()));
        }

        public void ForceOpenAiAnalysis()
        {
            if (state == null) state = HealthState.Load(statePath);
            RunOpenAiAnalysis(true);
        }

        private void SendOpenAiAnalysisIfDue()
        {
            if (!config.EnableOpenAiLogAnalysis) return;

            DateTime now = DateTime.UtcNow;
            if (state.LastOpenAiAnalysisUtc.HasValue &&
                (now - state.LastOpenAiAnalysisUtc.Value).TotalMinutes < config.OpenAIAnalysisIntervalMinutes)
            {
                return;
            }

            RunOpenAiAnalysis(false);
        }

        private void RunOpenAiAnalysis(bool forced)
        {
            if (!config.EnableOpenAiLogAnalysis && !forced) return;

            try
            {
                if (!openAiAnalyzer.IsConfigured)
                {
                    logger.Warn("OpenAI analysis skipped: API key environment variable is not visible: " + config.OpenAIApiKeyEnvironmentVariable);
                    state.LastOpenAiAnalysisUtc = DateTime.UtcNow;
                    Save();
                    return;
                }

                string payload = compactLogSampler.BuildPayload(state);
                OpenAiAnalysisResult result = openAiAnalyzer.Analyze(payload);
                state.LastOpenAiAnalysisUtc = DateTime.UtcNow;
                Save();

                logger.Info("OpenAI analysis completed alertable=" + result.Alertable + " score=" + result.Score.ToString(CultureInfo.InvariantCulture) + " title=" + result.Title);

                if (forced)
                {
                    dispatcher.SendExternal(Alert.SystemAlert(
                        "OPENAI-LOG-ANALYSIS-TEST",
                        "OpenAI log analysis test result",
                        Math.Max(config.MinimumEmailScore, result.Score),
                        result.ToBody(),
                        "No action required if you intentionally ran the OpenAI analysis test.",
                        ServiceEntity()));
                }
                else if (result.Alertable && result.Score >= config.OpenAIAnalysisScoreThreshold)
                {
                    if (config.BaselineLearningMode && result.Score < config.OpenAIAnalysisBaselineEmailMinimumScore)
                    {
                        logger.Warn("OpenAI alert suppressed during baseline learning score=" + result.Score.ToString(CultureInfo.InvariantCulture) +
                            " baseline_email_minimum=" + config.OpenAIAnalysisBaselineEmailMinimumScore.ToString(CultureInfo.InvariantCulture) +
                            " title=" + result.Title);
                        return;
                    }

                    dispatcher.SendExternal(Alert.SystemAlert(
                        "OPENAI-LOG-ANALYSIS-ALERT",
                        "OpenAI flagged security-relevant log activity",
                        Math.Max(result.Score, config.MinimumEmailScore),
                        result.ToBody(),
                        result.RecommendedAction,
                        ServiceEntity()));
                }
            }
            catch (Exception ex)
            {
                logger.Error("OpenAI analysis failed: " + ex.Message);
            }
        }

        private void Save()
        {
            try
            {
                state.Save(statePath);
            }
            catch (Exception ex)
            {
                logger.Error("Health state save failed: " + ex.Message);
            }
        }

        private static string Format(DateTime? value)
        {
            return value.HasValue ? Format(value.Value) : "";
        }

        private static string Format(DateTime value)
        {
            return value.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ", CultureInfo.InvariantCulture);
        }

        private string ServiceEntity()
        {
            return "service=" + config.ServiceName;
        }
    }
}
