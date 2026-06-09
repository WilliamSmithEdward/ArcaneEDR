using System;
using System.Collections.Generic;

namespace ArcaneEDR
{
    internal sealed class AlertDispatcher
    {
        private readonly MonitorConfig config;
        private readonly FileLogger logger;
        private readonly IAlertSink alertSink;
        private readonly ResponseManager responseManager;
        private readonly ExternalAlertRetryQueue retryQueue;
        private readonly IncidentStore incidentStore;
        private readonly LowValueRepeatDampener lowValueRepeatDampener;
        private readonly AgentActivityLedger agentActivityLedger;
        private readonly DetectionPolicyEngine detectionPolicyEngine;
        private readonly Dictionary<string, DateTime> cooldowns = new Dictionary<string, DateTime>(StringComparer.OrdinalIgnoreCase);
        private readonly Queue<DateTime> externalSends = new Queue<DateTime>();
        private DateTime lastThrottleWarningUtc = DateTime.MinValue;

        public AlertDispatcher(MonitorConfig config, FileLogger logger, IAlertSink alertSink, ResponseManager responseManager)
        {
            this.config = config;
            this.logger = logger;
            this.alertSink = alertSink;
            this.responseManager = responseManager;
            retryQueue = new ExternalAlertRetryQueue(config, logger);
            incidentStore = new IncidentStore(config, logger);
            lowValueRepeatDampener = new LowValueRepeatDampener(config);
            agentActivityLedger = new AgentActivityLedger(config, logger);
            detectionPolicyEngine = new DetectionPolicyEngine(config, logger);
        }

        public void Dispatch(IEnumerable<Alert> alerts)
        {
            RetryExternalAlerts();

            int sentThisDispatch = 0;
            foreach (Alert alert in alerts)
            {
                try
                {
                    DispatchOne(alert, ref sentThisDispatch);
                }
                catch (Exception ex)
                {
                    logger.Error("Alert dispatch failed; continuing with remaining alerts: " + ex);
                }
            }
        }

        private void DispatchOne(Alert alert, ref int sentThisDispatch)
        {
            if (alert == null) return;
            Alert annotatedAlert = Annotate(alert);

            if (AlertRulePolicy.IsDisabled(config, annotatedAlert))
            {
                logger.Warn("Alert suppressed by rule policy: " + annotatedAlert.RuleId +
                    " category=" + annotatedAlert.Category + ".");
                return;
            }

            detectionPolicyEngine.Apply(annotatedAlert);

            if (IsCoolingDown(annotatedAlert))
            {
                return;
            }

            Remember(annotatedAlert);
            logger.Alert(annotatedAlert);
            incidentStore.Record(annotatedAlert);
            agentActivityLedger.Record(annotatedAlert);
            responseManager.Handle(annotatedAlert);

            if (ShouldSendExternal(annotatedAlert, sentThisDispatch))
            {
                string failureReason;
                if (TrySendExternalAlert(annotatedAlert, out failureReason))
                {
                    RememberExternalSend();
                    sentThisDispatch++;
                }
                else
                {
                    QueueFailedExternal(annotatedAlert, failureReason);
                }
            }
        }

        public void SendExternal(Alert alert)
        {
            if (alert == null) return;
            Alert annotatedAlert = Annotate(alert);
            if (AlertRulePolicy.IsDisabled(config, annotatedAlert))
            {
                logger.Warn("External alert suppressed by rule policy: " + annotatedAlert.RuleId +
                    " category=" + annotatedAlert.Category + ".");
                return;
            }

            detectionPolicyEngine.Apply(annotatedAlert);
            logger.Alert(annotatedAlert);
            incidentStore.Record(annotatedAlert);
            agentActivityLedger.Record(annotatedAlert);
            if (annotatedAlert.ExternalSuppressedByPolicy)
            {
                logger.Info("External alert delivery suppressed by detection policy: " + annotatedAlert.RuleId + ".");
                return;
            }

            bool hourlyLimitExempt = IsExternalHourlyLimitExempt(annotatedAlert);
            if (!hourlyLimitExempt && IsExternalHourlyLimitReached())
            {
                WarnThrottled("hourly limit reached");
                return;
            }

            string failureReason;
            if (TrySendExternalAlert(annotatedAlert, out failureReason))
            {
                if (!hourlyLimitExempt) RememberExternalSend();
            }
            else
            {
                QueueFailedExternal(annotatedAlert, failureReason);
            }
        }

        private Alert Annotate(Alert alert)
        {
            AlertRuleCatalog.Annotate(alert);
            Alert reasonedAlert = AlertReasonAnnotator.Annotate(alert);
            Alert agentAlert = AgentAlertAnnotator.Annotate(config, reasonedAlert);
            return MaintenanceAlertAnnotator.Annotate(config, agentAlert);
        }

        private bool IsCoolingDown(Alert alert)
        {
            DateTime last;
            if (!cooldowns.TryGetValue(alert.CooldownKey, out last))
            {
                return false;
            }

            return (DateTime.UtcNow - last).TotalSeconds < config.AlertCooldownSeconds;
        }

        private void Remember(Alert alert)
        {
            cooldowns[alert.CooldownKey] = DateTime.UtcNow;
        }

        private bool TrySendExternalAlert(Alert alert, out string failureReason)
        {
            failureReason = "";
            if (alertSink.IsConfigured)
            {
                try
                {
                    if (alertSink.Send(alert))
                    {
                        return true;
                    }

                    failureReason = "";
                    logger.Info("External alert delivery skipped by sink routing: " + alert.RuleId + ".");
                    return false;
                }
                catch (Exception ex)
                {
                    failureReason = ex.Message;
                    logger.Error("External alert send failed: " + failureReason);
                    return false;
                }
            }
            else if (config.RequireExternalAlerting)
            {
                failureReason = alertSink.MissingConfigurationReason;
                logger.Error("External alerting is required but unavailable. Alert was logged locally only: " + alert.RuleId + ". Reason: " + failureReason);
            }

            return false;
        }

        private void QueueFailedExternal(Alert alert, string failureReason)
        {
            if (!config.ExternalAlertRetryEnabled) return;
            if (!alertSink.IsConfigured) return;
            if (String.IsNullOrWhiteSpace(failureReason)) return;

            retryQueue.Enqueue(alert, failureReason);
        }

        private void RetryExternalAlerts()
        {
            retryQueue.RetryDue(TrySendExternalRetry);
        }

        private bool TrySendExternalRetry(Alert alert, out string failureReason)
        {
            failureReason = "";
            bool hourlyLimitExempt = IsExternalHourlyLimitExempt(alert);
            if (!hourlyLimitExempt && IsExternalHourlyLimitReached())
            {
                WarnThrottled("hourly limit reached");
                return false;
            }

            if (TrySendExternalAlert(alert, out failureReason))
            {
                if (!hourlyLimitExempt) RememberExternalSend();
                return true;
            }

            return false;
        }

        private bool ShouldSendExternal(Alert alert, int sentThisDispatch)
        {
            if (alert.ExternalSuppressedByPolicy)
            {
                WarnThrottled("detection policy suppressed external delivery");
                return false;
            }

            bool forceExternal = alert.ExternalForcedByPolicy;
            int minimumExternalScore = AlertRulePolicy.MinimumExternalScore(config, alert);
            if (!forceExternal && alert.Score < minimumExternalScore) return false;

            if (!config.HasExternalAlertProviderEligibleForScore(alert.Score))
            {
                WarnThrottled("no configured alert sink eligible for alert score");
                return false;
            }

            if (!forceExternal &&
                alert.MaintenanceContext &&
                alert.Score < config.MaintenanceContextExternalAlertMinimumScore)
            {
                WarnThrottled("maintenance context below external alert threshold");
                return false;
            }

            if (!forceExternal &&
                AlertRuleTaxonomy.IsResponseRule(alert.RuleId) &&
                alert.Score < config.ResponseFollowUpExternalAlertMinimumScore)
            {
                WarnThrottled("response follow-up below external alert threshold");
                return false;
            }

            if (!forceExternal &&
                config.BaselineLearningMode &&
                alert.Score < config.BaselineLearningEmailMinimumScore)
            {
                return false;
            }

            if (!forceExternal &&
                TermGroupRules.MatchesAnyGroup(AlertText(alert), config.ExternalAlertSuppressionTermGroups))
            {
                WarnThrottled("configured suppression group matched");
                return false;
            }

            if (!forceExternal && lowValueRepeatDampener.ShouldDampen(alert))
            {
                WarnThrottled("repeated low-value alert dampened");
                return false;
            }

            if (config.ExternalAlertMaxPerDispatch > 0 && sentThisDispatch >= config.ExternalAlertMaxPerDispatch)
            {
                WarnThrottled("per-dispatch limit reached");
                return false;
            }

            PruneExternalSendWindow();
            if (IsExternalHourlyLimitReachedWithoutPrune())
            {
                WarnThrottled("hourly limit reached");
                return false;
            }

            return true;
        }

        private bool IsExternalHourlyLimitReached()
        {
            PruneExternalSendWindow();
            return IsExternalHourlyLimitReachedWithoutPrune();
        }

        private bool IsExternalHourlyLimitReachedWithoutPrune()
        {
            return config.ExternalAlertMaxPerHour > 0 && externalSends.Count >= config.ExternalAlertMaxPerHour;
        }

        private static bool IsExternalHourlyLimitExempt(Alert alert)
        {
            return alert != null &&
                (AlertRuleTaxonomy.IsDailySummaryRule(alert.RuleId) ||
                    AlertRuleTaxonomy.IsServiceLifecycleRule(alert.RuleId));
        }

        private void RememberExternalSend()
        {
            externalSends.Enqueue(DateTime.UtcNow);
            PruneExternalSendWindow();
        }

        private void PruneExternalSendWindow()
        {
            DateTime cutoff = DateTime.UtcNow.AddHours(-1);
            while (externalSends.Count > 0 && externalSends.Peek() < cutoff)
            {
                externalSends.Dequeue();
            }
        }

        private void WarnThrottled(string reason)
        {
            DateTime now = DateTime.UtcNow;
            if ((now - lastThrottleWarningUtc).TotalMinutes < 5) return;
            lastThrottleWarningUtc = now;
            logger.Warn("External alert delivery suppressed: " + reason + ".");
        }

        private static string AlertText(Alert alert)
        {
            return (alert.RuleId ?? "") + " " +
                (alert.Title ?? "") + " " +
                (alert.Body ?? "") + " " +
                (alert.EntitySummary ?? "");
        }
    }
}
