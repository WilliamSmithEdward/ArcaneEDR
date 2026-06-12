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
        private readonly ExternalAlertGroupingPlanner externalAlertGroupingPlanner;
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
            externalAlertGroupingPlanner = new ExternalAlertGroupingPlanner(config);
            agentActivityLedger = new AgentActivityLedger(config, logger);
            detectionPolicyEngine = new DetectionPolicyEngine(config, logger);
        }

        public void Dispatch(IEnumerable<Alert> alerts)
        {
            RetryExternalAlerts();

            int sentThisDispatch = 0;
            List<Alert> externalCandidates = new List<Alert>();
            foreach (Alert alert in alerts)
            {
                try
                {
                    DispatchOne(alert, externalCandidates);
                }
                catch (Exception ex)
                {
                    logger.Error("Alert dispatch failed; continuing with remaining alerts: " + ex);
                }
            }

            SendExternalCandidates(externalCandidates, ref sentThisDispatch);
        }

        private void DispatchOne(Alert alert, List<Alert> externalCandidates)
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

            bool externallyEligible = MarkExternalNotificationEligibility(annotatedAlert);
            Remember(annotatedAlert);
            logger.Alert(annotatedAlert);
            incidentStore.Record(annotatedAlert);
            agentActivityLedger.Record(annotatedAlert);
            responseManager.Handle(annotatedAlert);

            if (externallyEligible)
            {
                externalCandidates.Add(annotatedAlert);
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
            MarkExternalNotificationQueued(annotatedAlert, "Direct notification path queued for external delivery.");
            logger.Alert(annotatedAlert);
            incidentStore.Record(annotatedAlert);
            agentActivityLedger.Record(annotatedAlert);
            if (annotatedAlert.ExternalSuppressedByPolicy)
            {
                RecordExternalOutcome(annotatedAlert, "suppressed_by_policy", false, "Detection policy suppressed external delivery.");
                logger.Info("External alert delivery suppressed by detection policy: " + annotatedAlert.RuleId + ".");
                return;
            }

            bool hourlyLimitExempt = IsExternalHourlyLimitExempt(annotatedAlert);
            if (!hourlyLimitExempt && IsExternalHourlyLimitReached())
            {
                RecordExternalOutcome(annotatedAlert, "hourly_limit", false, "External alert hourly limit reached.");
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
                        RecordExternalOutcome(alert, "sent", true, "Delivered to at least one configured external alert sink.");
                        return true;
                    }

                    failureReason = "";
                    RecordExternalOutcome(alert, "skipped_by_sink", false, "Configured external sink routing did not accept this alert.");
                    logger.Info("External alert delivery skipped by sink routing: " + alert.RuleId + ".");
                    return false;
                }
                catch (Exception ex)
                {
                    failureReason = ex.Message;
                    RecordExternalOutcome(alert, "failed", false, failureReason);
                    logger.Error("External alert send failed: " + failureReason);
                    return false;
                }
            }
            else if (config.RequireExternalAlerting)
            {
                failureReason = alertSink.MissingConfigurationReason;
                RecordExternalOutcome(alert, "provider_unavailable", false, failureReason);
                logger.Error("External alerting is required but unavailable. Alert was logged locally only: " + alert.RuleId + ". Reason: " + failureReason);
            }
            else
            {
                RecordExternalOutcome(alert, "provider_unavailable", false, alertSink.MissingConfigurationReason);
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

        private void SendExternalCandidates(List<Alert> externalCandidates, ref int sentThisDispatch)
        {
            if (externalCandidates == null || externalCandidates.Count == 0) return;

            List<Alert> plannedAlerts = externalAlertGroupingPlanner.Plan(externalCandidates);
            RecordGroupedCandidateOutcomes(externalCandidates, plannedAlerts);
            foreach (Alert plannedAlert in plannedAlerts)
            {
                try
                {
                    string blockedStatus;
                    string blockedReason;
                    if (!ShouldSendPlannedExternal(plannedAlert, sentThisDispatch, out blockedStatus, out blockedReason))
                    {
                        RecordExternalOutcome(plannedAlert, blockedStatus, false, blockedReason);
                        continue;
                    }

                    string failureReason;
                    if (TrySendExternalAlert(plannedAlert, out failureReason))
                    {
                        RememberExternalSend();
                        sentThisDispatch++;
                    }
                    else
                    {
                        QueueFailedExternal(plannedAlert, failureReason);
                    }
                }
                catch (Exception ex)
                {
                    logger.Error("External alert dispatch failed; continuing with remaining planned alerts: " + ex);
                }
            }
        }

        private void RecordGroupedCandidateOutcomes(List<Alert> externalCandidates, List<Alert> plannedAlerts)
        {
            if (externalCandidates == null || externalCandidates.Count == 0) return;
            if (plannedAlerts == null || plannedAlerts.Count == 0) return;

            HashSet<Alert> plannedOriginals = new HashSet<Alert>(plannedAlerts);
            foreach (Alert candidate in externalCandidates)
            {
                if (candidate == null || plannedOriginals.Contains(candidate)) continue;
                RecordExternalOutcome(
                    candidate,
                    "grouped",
                    false,
                    "This local alert was grouped into a related external notification instead of sending its own message.");
            }
        }

        private bool MarkExternalNotificationEligibility(Alert alert)
        {
            string reason;
            if (ExternalAlertEligibility.ShouldDispatch(config, alert, out reason))
            {
                MarkExternalNotificationQueued(alert, "Eligible for external notification; awaiting dispatch planning.");
                return true;
            }

            string status = ExternalBlockedStatus(alert, reason);
            string explanation = ExternalBlockedReason(alert, status, reason);
            alert.MarkExternalNotification(status, explanation, false);
            if (!String.IsNullOrWhiteSpace(reason))
            {
                WarnThrottled(reason);
            }

            return false;
        }

        private void MarkExternalNotificationQueued(Alert alert, string reason)
        {
            if (alert == null) return;
            alert.MarkExternalNotification("queued", reason, false);
        }

        private void RecordExternalOutcome(Alert alert, string status, bool sent, string reason)
        {
            if (alert == null) return;
            alert.MarkExternalNotification(status, reason, sent);
            logger.AlertNotificationOutcome(alert, config.ExternalAlertProvider);
        }

        private string ExternalBlockedStatus(Alert alert, string reason)
        {
            if (alert == null) return "not_evaluated";
            if (alert.ExternalSuppressedByPolicy) return "suppressed_by_policy";
            if (ContainsIgnoreCase(reason, "no configured alert sink")) return "provider_unavailable";
            if (ContainsIgnoreCase(reason, "maintenance context")) return "maintenance_threshold";
            if (ContainsIgnoreCase(reason, "response follow-up")) return "response_threshold";
            if (ContainsIgnoreCase(reason, "suppression group")) return "suppression_group";
            if (config.BaselineLearningMode && alert.Score < config.BaselineLearningEmailMinimumScore) return "baseline_learning";
            if (alert.Score < AlertRulePolicy.MinimumExternalScore(config, alert)) return "below_threshold";
            if (!String.IsNullOrWhiteSpace(reason)) return "not_sent";
            return "below_threshold";
        }

        private string ExternalBlockedReason(Alert alert, string status, string reason)
        {
            if (!String.IsNullOrWhiteSpace(reason)) return reason;

            if (status.Equals("below_threshold", StringComparison.OrdinalIgnoreCase))
            {
                return "Alert did not meet the current external notification threshold.";
            }

            if (status.Equals("baseline_learning", StringComparison.OrdinalIgnoreCase))
            {
                return "Baseline learning mode kept this alert local under the current baseline notification threshold.";
            }

            if (status.Equals("suppressed_by_policy", StringComparison.OrdinalIgnoreCase))
            {
                return "Detection policy suppressed external delivery.";
            }

            if (status.Equals("provider_unavailable", StringComparison.OrdinalIgnoreCase))
            {
                return alertSink.MissingConfigurationReason;
            }

            return "External notification was not sent.";
        }

        private static bool ContainsIgnoreCase(string value, string needle)
        {
            return !String.IsNullOrWhiteSpace(value) &&
                value.IndexOf(needle, StringComparison.OrdinalIgnoreCase) >= 0;
        }

        private bool ShouldSendPlannedExternal(Alert alert, int sentThisDispatch, out string status, out string reason)
        {
            status = "";
            reason = "";
            bool forceExternal = alert != null && alert.ExternalForcedByPolicy;
            if (!forceExternal && lowValueRepeatDampener.ShouldDampen(alert))
            {
                status = "dampened";
                reason = "Repeated low-value alert dampened.";
                WarnThrottled("repeated low-value alert dampened");
                return false;
            }

            if (config.ExternalAlertMaxPerDispatch > 0 && sentThisDispatch >= config.ExternalAlertMaxPerDispatch)
            {
                status = "per_dispatch_limit";
                reason = "External alert per-dispatch limit reached.";
                WarnThrottled("per-dispatch limit reached");
                return false;
            }

            PruneExternalSendWindow();
            if (IsExternalHourlyLimitReachedWithoutPrune())
            {
                status = "hourly_limit";
                reason = "External alert hourly limit reached.";
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

    }
}
