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
        private readonly IAiAnalysisProvider aiAnalysisProvider;
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
            IAiAnalysisProvider aiAnalysisProvider,
            CompactLogSampler compactLogSampler)
        {
            this.config = config;
            this.logger = logger;
            this.dispatcher = dispatcher;
            this.aiAnalysisProvider = aiAnalysisProvider;
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
                    recovered ? AlertRuleTaxonomy.RuleServiceRecoveredAfterUncleanStop : AlertRuleTaxonomy.RuleServiceStarted,
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
                    AlertRuleTaxonomy.RuleServiceStopped,
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
            SendAiAnalysisIfDue();
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

            DailyReportBuilder reportBuilder = new DailyReportBuilder(
                config,
                state,
                runId,
                startedUtc,
                currentRunPolls,
                currentRunAlerts,
                currentRunPollFailures);
            DailyReportSnapshot snapshot = reportBuilder.BuildSnapshot(now);
            AiAnalysisResult dailyAiResult = null;
            string dailyAiStatus = "disabled";

            if (config.EnableAIAnalysis && config.EnableDailySummaryAIAnalysis)
            {
                dailyAiStatus = "not_configured";
                if (aiAnalysisProvider.IsConfigured)
                {
                    try
                    {
                        string payload = reportBuilder.BuildAiPayload(snapshot);
                        dailyAiResult = aiAnalysisProvider.AnalyzeDailyReport(payload);
                        dailyAiStatus = "completed";
                        logger.Info("AI daily report analysis completed provider=" + aiAnalysisProvider.ProviderName +
                            " alertable=" +
                            dailyAiResult.Alertable +
                            " score=" + dailyAiResult.Score.ToString(CultureInfo.InvariantCulture) +
                            " title=" + dailyAiResult.Title);
                    }
                    catch (Exception ex)
                    {
                        dailyAiStatus = "failed: " + ex.Message;
                        logger.Error("AI daily report analysis failed: " + ex.Message);
                    }
                }
            }

            string body = reportBuilder.BuildReport(snapshot, dailyAiResult, dailyAiStatus);
            string archiveJson = reportBuilder.BuildArchiveJson(snapshot, dailyAiResult, dailyAiStatus);
            if (config.DailyReportDestinationEnabled("LocalArchive"))
            {
                DailyReportArchive archive = new DailyReportArchive(config, logger);
                archive.Save(snapshot, body, archiveJson);
            }

            if (config.DailyReportDestinationEnabled("Webhook"))
            {
                DailyReportHttpSink reportSink = new DailyReportHttpSink(config, logger, new EnvironmentSecretProvider());
                if (reportSink.IsConfigured)
                {
                    try
                    {
                        reportSink.Send(snapshot, archiveJson);
                    }
                    catch (Exception ex)
                    {
                        logger.Error("Daily report webhook delivery failed: " + ex.Message);
                    }
                }
                else
                {
                    logger.Warn("Daily report webhook skipped: " + reportSink.MissingConfigurationReason);
                }
            }

            if (config.DailyReportDestinationEnabled("ExternalAlertSinks"))
            {
                dispatcher.SendExternal(Alert.SystemAlert(
                    AlertRuleTaxonomy.RuleServiceDailySummary,
                    "Daily Arcane EDR report",
                    config.DailySummaryScore,
                    body,
                    "Review the daily report sections for high-signal activity, collector health, agent activity, and tuning notes.",
                    ServiceEntity()));
            }
            else
            {
                logger.Info("Daily report external delivery skipped by DailyReportDestinations.");
            }
        }

        public void ForceAiAnalysis()
        {
            if (state == null) state = HealthState.Load(statePath);
            RunAiAnalysis(true);
        }

        private void SendAiAnalysisIfDue()
        {
            if (!config.EnableAIAnalysis) return;

            DateTime now = DateTime.UtcNow;
            if (state.LastAIAnalysisUtc.HasValue &&
                (now - state.LastAIAnalysisUtc.Value).TotalMinutes < config.AIAnalysisIntervalMinutes)
            {
                return;
            }

            RunAiAnalysis(false);
        }

        private void RunAiAnalysis(bool forced)
        {
            if (!config.EnableAIAnalysis && !forced) return;

            try
            {
                if (!aiAnalysisProvider.IsConfigured)
                {
                    logger.Warn("AI analysis skipped: " + aiAnalysisProvider.MissingConfigurationReason);
                    state.LastAIAnalysisUtc = DateTime.UtcNow;
                    Save();
                    return;
                }

                string payload = compactLogSampler.BuildPayload(state);
                AiAnalysisResult result = aiAnalysisProvider.Analyze(payload);
                state.LastAIAnalysisUtc = DateTime.UtcNow;
                Save();

                logger.Info("AI analysis completed provider=" + aiAnalysisProvider.ProviderName + " alertable=" + result.Alertable + " score=" + result.Score.ToString(CultureInfo.InvariantCulture) + " title=" + result.Title);

                if (forced)
                {
                    dispatcher.SendExternal(Alert.SystemAlert(
                        AlertRuleTaxonomy.RuleAiLogAnalysisTest,
                        "AI log analysis test result",
                        Math.Max(config.MinimumEmailScore, result.Score),
                        result.ToBody(),
                        "No action required if you intentionally ran the AI analysis test.",
                        ServiceEntity()));
                }
                else if (result.Alertable && result.Score >= config.AIAnalysisScoreThreshold)
                {
                    if (config.BaselineLearningMode && result.Score < config.AIAnalysisBaselineEmailMinimumScore)
                    {
                        logger.Warn("AI analysis alert suppressed during baseline learning score=" + result.Score.ToString(CultureInfo.InvariantCulture) +
                            " baseline_email_minimum=" + config.AIAnalysisBaselineEmailMinimumScore.ToString(CultureInfo.InvariantCulture) +
                            " title=" + result.Title);
                        return;
                    }

                    dispatcher.SendExternal(Alert.SystemAlert(
                        AlertRuleTaxonomy.RuleAiLogAnalysisAlert,
                        "AI analysis flagged security-relevant log activity",
                        Math.Max(result.Score, config.MinimumEmailScore),
                        result.ToBody(),
                        result.RecommendedAction,
                        ServiceEntity()));
                }
            }
            catch (Exception ex)
            {
                if (!forced)
                {
                    state.LastAIAnalysisUtc = DateTime.UtcNow;
                    Save();
                }

                logger.Error("AI analysis failed: " + ex.Message);
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
