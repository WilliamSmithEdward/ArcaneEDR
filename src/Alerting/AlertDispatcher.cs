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
        private readonly Dictionary<string, DateTime> cooldowns = new Dictionary<string, DateTime>(StringComparer.OrdinalIgnoreCase);
        private readonly Queue<DateTime> externalSends = new Queue<DateTime>();
        private DateTime lastThrottleWarningUtc = DateTime.MinValue;

        public AlertDispatcher(MonitorConfig config, FileLogger logger, IAlertSink alertSink, ResponseManager responseManager)
        {
            this.config = config;
            this.logger = logger;
            this.alertSink = alertSink;
            this.responseManager = responseManager;
        }

        public void Dispatch(IEnumerable<Alert> alerts)
        {
            int sentThisDispatch = 0;
            foreach (Alert alert in alerts)
            {
                if (IsCoolingDown(alert))
                {
                    continue;
                }

                Remember(alert);
                logger.Alert(alert);
                responseManager.Handle(alert);

                if (ShouldSendExternal(alert, sentThisDispatch))
                {
                    SendExternalAlert(alert);
                    RememberExternalSend();
                    sentThisDispatch++;
                }
            }
        }

        public void SendExternal(Alert alert)
        {
            logger.Alert(alert);
            SendExternalAlert(alert);
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

        private void SendExternalAlert(Alert alert)
        {
            if (alertSink.IsConfigured)
            {
                try
                {
                    alertSink.Send(alert);
                }
                catch (Exception ex)
                {
                    logger.Error("External alert send failed: " + ex.Message);
                }
            }
            else if (config.RequireExternalAlerting)
            {
                logger.Error("External alerting is required but unavailable. Alert was logged locally only: " + alert.RuleId + ". Reason: " + alertSink.MissingConfigurationReason);
            }
        }

        private bool ShouldSendExternal(Alert alert, int sentThisDispatch)
        {
            if (alert.Score < config.MinimumEmailScore) return false;

            if (config.BaselineLearningMode && alert.Score < config.BaselineLearningEmailMinimumScore)
            {
                return false;
            }

            if (TermGroupRules.MatchesAnyGroup(AlertText(alert), config.ExternalAlertSuppressionTermGroups))
            {
                WarnThrottled("configured suppression group matched");
                return false;
            }

            if (config.ExternalAlertMaxPerDispatch > 0 && sentThisDispatch >= config.ExternalAlertMaxPerDispatch)
            {
                WarnThrottled("per-dispatch limit reached");
                return false;
            }

            PruneExternalSendWindow();
            if (config.ExternalAlertMaxPerHour > 0 && externalSends.Count >= config.ExternalAlertMaxPerHour)
            {
                WarnThrottled("hourly limit reached");
                return false;
            }

            return true;
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
            logger.Warn("External alert email suppressed: " + reason + ".");
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
