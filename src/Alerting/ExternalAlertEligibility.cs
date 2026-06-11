namespace ArcaneEDR
{
    internal static class ExternalAlertEligibility
    {
        public static bool ShouldDispatch(MonitorConfig config, Alert alert, out string reason)
        {
            return Evaluate(
                config,
                alert,
                false,
                false,
                true,
                true,
                out reason);
        }

        public static bool WouldQualifyBeforeRateLimits(
            MonitorConfig config,
            Alert alert,
            bool assumeBaselineLearningOff,
            bool includeSuppressionGroups)
        {
            string reason;
            return Evaluate(
                config,
                alert,
                assumeBaselineLearningOff,
                true,
                includeSuppressionGroups,
                false,
                out reason);
        }

        private static bool Evaluate(
            MonitorConfig config,
            Alert alert,
            bool assumeBaselineLearningOff,
            bool includeDirectExternalPath,
            bool includeSuppressionGroups,
            bool includeResponseFollowUpThreshold,
            out string reason)
        {
            reason = "";
            if (config == null || alert == null) return false;

            if (alert.ExternalSuppressedByPolicy)
            {
                reason = "detection policy suppressed external delivery";
                return false;
            }

            if (alert.ExternalForcedByPolicy)
            {
                return ProviderEligible(config, alert, out reason);
            }

            if (includeDirectExternalPath && AlertRuleTaxonomy.IsDirectExternalRule(alert.RuleId))
            {
                return ProviderEligible(config, alert, out reason);
            }

            if (alert.Score < AlertRulePolicy.MinimumExternalScore(config, alert)) return false;

            if (!ProviderEligible(config, alert, out reason))
            {
                return false;
            }

            if (alert.MaintenanceContext && alert.Score < config.MaintenanceContextExternalAlertMinimumScore)
            {
                reason = "maintenance context below external alert threshold";
                return false;
            }

            if (includeResponseFollowUpThreshold &&
                AlertRuleTaxonomy.IsResponseRule(alert.RuleId) &&
                alert.Score < config.ResponseFollowUpExternalAlertMinimumScore)
            {
                reason = "response follow-up below external alert threshold";
                return false;
            }

            if (!assumeBaselineLearningOff &&
                config.BaselineLearningMode &&
                alert.Score < config.BaselineLearningEmailMinimumScore)
            {
                return false;
            }

            if (includeSuppressionGroups &&
                TermGroupRules.MatchesAnyGroup(AlertText.Build(alert), config.ExternalAlertSuppressionTermGroups))
            {
                reason = "configured suppression group matched";
                return false;
            }

            return true;
        }

        private static bool ProviderEligible(MonitorConfig config, Alert alert, out string reason)
        {
            reason = "";
            if (config.HasExternalAlertProviderEligibleForScore(alert.Score)) return true;

            reason = "no configured alert sink eligible for alert score";
            return false;
        }

    }
}
