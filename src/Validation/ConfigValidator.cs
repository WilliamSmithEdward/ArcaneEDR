using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Diagnostics.Eventing.Reader;
using System.IO;
using System.ServiceProcess;

namespace ArcaneEDR
{
    internal static class ConfigValidator
    {
        public static int Run(string baseDirectory)
        {
            return Run(baseDirectory, "");
        }

        public static int Run(string baseDirectory, string explicitConfigPath)
        {
            List<string> errors = new List<string>();
            List<string> warnings = new List<string>();
            MonitorConfig config = null;

            try
            {
                config = MonitorConfig.Load(baseDirectory, explicitConfigPath);
                Pass("Loaded config: " + config.ConfigPath);
            }
            catch (Exception ex)
            {
                Fail(errors, "Config load failed: " + ex.Message);
                return Finish(errors, warnings);
            }

            ValidateRemovedConfigKeys(config, errors);
            ValidateBasicSettings(config, errors, warnings);
            ValidateLogDirectory(config, errors);
            ValidateSecrets(config, errors, warnings);
            ValidateEventLogAccess(config, warnings);
            ValidateSysmon(config, warnings);
            ValidateCustomRules(config, errors, warnings);
            ValidateDetectionPolicy(config, errors, warnings);

            return Finish(errors, warnings);
        }

        private static void ValidateBasicSettings(MonitorConfig config, List<string> errors, List<string> warnings)
        {
            if (String.IsNullOrWhiteSpace(config.ProductName)) Fail(errors, "ProductName must be configured.");
            if (String.IsNullOrWhiteSpace(config.ServiceName)) Fail(errors, "ServiceName must be configured.");
            if (String.IsNullOrWhiteSpace(config.ServiceDisplayName)) Fail(errors, "ServiceDisplayName must be configured.");
            if (String.IsNullOrWhiteSpace(config.ServiceDescription)) Warn(warnings, "ServiceDescription is empty.");
            if (config.PollIntervalSeconds <= 0) Fail(errors, "PollIntervalSeconds must be greater than zero.");
            if (config.AlertCooldownSeconds < 0) Fail(errors, "AlertCooldownSeconds must not be negative.");
            if (config.ExternalAlertMaxPerDispatch < 0) Fail(errors, "ExternalAlertMaxPerDispatch must not be negative.");
            if (config.ExternalAlertMaxPerHour < 0) Fail(errors, "ExternalAlertMaxPerHour must not be negative.");
            if (config.ExternalAlertRetryIntervalSeconds <= 0) Fail(errors, "ExternalAlertRetryIntervalSeconds must be greater than zero.");
            if (config.ExternalAlertRetryMaxIntervalSeconds < config.ExternalAlertRetryIntervalSeconds) Warn(warnings, "ExternalAlertRetryMaxIntervalSeconds is lower than ExternalAlertRetryIntervalSeconds; retry backoff will be capped immediately.");
            if (config.ExternalAlertRetryMaxAttempts < 1) Fail(errors, "ExternalAlertRetryMaxAttempts must be at least 1.");
            if (config.ExternalAlertRetryMaxQueued < 0) Fail(errors, "ExternalAlertRetryMaxQueued must not be negative.");
            if (config.ExternalAlertRetryMaxPerPoll < 0) Fail(errors, "ExternalAlertRetryMaxPerPoll must not be negative.");
            ValidateExternalAlertProviders(config, errors, warnings);
            ValidateTermGroups(config.ExternalAlertSuppressionTermGroups, "ExternalAlertSuppressionTermGroups", warnings);
            ValidateLowValueRepeatDampening(config, errors, warnings);
            ValidateTermGroups(config.MaintenanceContextTermGroups, "MaintenanceContextTermGroups", warnings);
            if (config.MaintenanceContextExternalAlertMinimumScore < 0 || config.MaintenanceContextExternalAlertMinimumScore > 100) Warn(warnings, "MaintenanceContextExternalAlertMinimumScore is outside the usual 0-100 range.");
            ValidateMaintenanceSessionMarkers(config, errors, warnings);
            if (config.BaselineLearningEmailMinimumScore < 0 || config.BaselineLearningEmailMinimumScore > 100) Warn(warnings, "BaselineLearningEmailMinimumScore is outside the usual 0-100 range.");
            if (config.AIAnalysisBaselineEmailMinimumScore < 0 || config.AIAnalysisBaselineEmailMinimumScore > 100) Warn(warnings, "AIAnalysisBaselineEmailMinimumScore is outside the usual 0-100 range.");
            if (config.AIAnalysisMinimumIncludedAlertScore < 0 || config.AIAnalysisMinimumIncludedAlertScore > 100) Warn(warnings, "AIAnalysisMinimumIncludedAlertScore is outside the usual 0-100 range.");
            if (config.AIAnalysisBaselineMinimumIncludedAlertScore < 0 || config.AIAnalysisBaselineMinimumIncludedAlertScore > 100) Warn(warnings, "AIAnalysisBaselineMinimumIncludedAlertScore is outside the usual 0-100 range.");
            if (config.AIAnalysisTimeoutSeconds <= 0) Fail(errors, "AIAnalysisTimeoutSeconds must be greater than zero.");
            ValidateAiAnalysisProvider(config, errors, warnings);
            ValidateDailySummarySchedule(config, errors, warnings);
            ValidateDailyReportConfig(config, errors, warnings);
            if (config.MinimumEmailScore < 0 || config.MinimumEmailScore > 100) Warn(warnings, "MinimumEmailScore is outside the usual 0-100 range.");
            ValidateRulePolicy(config, warnings);
            ValidateUnifiedPolicyFile(config, errors);
            if (config.AIAnalysisMaxChars > 20000) Warn(warnings, "AIAnalysisMaxChars is above 20000; compact analysis may use more tokens than intended.");
            ValidateHighSignalFileDetection(config, warnings);
            if (config.BrevoTimeoutSeconds <= 0) Fail(errors, "BrevoTimeoutSeconds must be greater than zero.");
            if (config.SmtpPort < 1 || config.SmtpPort > 65535) Fail(errors, "SmtpPort must be between 1 and 65535.");
            if (config.SmtpTimeoutSeconds <= 0) Fail(errors, "SmtpTimeoutSeconds must be greater than zero.");
            if (config.WebhookTimeoutSeconds <= 0) Fail(errors, "WebhookTimeoutSeconds must be greater than zero.");
            if (config.GenericHttpApiTimeoutSeconds <= 0) Fail(errors, "GenericHttpApiTimeoutSeconds must be greater than zero.");
            if (config.WindowsEventLogAlertEventId < 1 || config.WindowsEventLogAlertEventId > 65535) Fail(errors, "WindowsEventLogAlertEventId must be between 1 and 65535.");
            if (config.PersistEventLogWatermarks && String.IsNullOrWhiteSpace(config.EventLogWatermarkFile)) Fail(errors, "EventLogWatermarkFile must be configured when PersistEventLogWatermarks is enabled.");
            ValidateCollectorConfig(config, warnings);
            ValidateRemoteEndpointEnrichment(config, errors, warnings);
            if (config.AuthSpecialPrivilegeRepeatDampeningMinutes <= 0) Fail(errors, "AuthSpecialPrivilegeRepeatDampeningMinutes must be greater than zero.");
            if (config.AuthSpecialPrivilegeRemoteCorrelationMinutes <= 0) Fail(errors, "AuthSpecialPrivilegeRemoteCorrelationMinutes must be greater than zero.");
            if (config.EnableIncidentGrouping)
            {
                if (String.IsNullOrWhiteSpace(config.IncidentStoreFile)) Fail(errors, "IncidentStoreFile must be configured when incident grouping is enabled.");
                if (config.IncidentWindowMinutes <= 0) Fail(errors, "IncidentWindowMinutes must be greater than zero.");
                if (config.IncidentMinimumScore < 0 || config.IncidentMinimumScore > 100) Warn(warnings, "IncidentMinimumScore is outside the usual 0-100 range.");
            }
            ValidateAgentProfile(config, warnings);
            ValidateAgentActivityLedger(config, errors, warnings);
            ValidateResponseConfig(config, errors, warnings);
        }

        private static void ValidateDailySummarySchedule(MonitorConfig config, List<string> errors, List<string> warnings)
        {
            if (!config.EnableDailySummary) return;

            if (String.IsNullOrWhiteSpace(config.DailySummaryLocalTime))
            {
                Warn(warnings, "DailySummaryLocalTime is empty; service will fall back to DailySummaryIntervalHours.");
            }
            else
            {
                TimeSpan parsed;
                if (!TimeSpan.TryParse(config.DailySummaryLocalTime, out parsed) || parsed < TimeSpan.Zero || parsed >= TimeSpan.FromDays(1))
                {
                    Fail(errors, "DailySummaryLocalTime must be HH:mm, for example 08:00.");
                }
                else
                {
                    Pass("Daily summary local time: " + config.DailySummaryLocalTime);
                }
            }

            if (!String.IsNullOrWhiteSpace(config.DailySummaryTimeZoneId))
            {
                try
                {
                    TimeZoneInfo zone = TimeZoneInfo.FindSystemTimeZoneById(config.DailySummaryTimeZoneId);
                    Pass("Daily summary time zone: " + zone.Id);
                }
                catch (Exception ex)
                {
                    Fail(errors, "DailySummaryTimeZoneId is not valid on this machine: " + config.DailySummaryTimeZoneId + " (" + ex.Message + ")");
                }
            }
        }

        private static void ValidateRulePolicy(MonitorConfig config, List<string> warnings)
        {
            foreach (string category in config.DisabledRuleCategories)
            {
                if (!AlertRuleCatalog.IsKnownCategory(category))
                {
                    Warn(warnings, "DisabledRuleCategories contains an unknown category: " + category);
                }
            }

            foreach (KeyValuePair<string, int> item in config.RuleMinimumEmailScores)
            {
                if (item.Value < 0 || item.Value > 100)
                {
                    Warn(warnings, "RuleMinimumEmailScores entry is outside the usual 0-100 range: " + item.Key + "=" + item.Value);
                }
            }

            foreach (KeyValuePair<string, int> item in config.CategoryMinimumEmailScores)
            {
                if (!AlertRuleCatalog.IsKnownCategory(item.Key))
                {
                    Warn(warnings, "CategoryMinimumEmailScores contains an unknown category: " + item.Key);
                }

                if (item.Value < 0 || item.Value > 100)
                {
                    Warn(warnings, "CategoryMinimumEmailScores entry is outside the usual 0-100 range: " + item.Key + "=" + item.Value);
                }
            }
        }

        private static void ValidateAiAnalysisProvider(MonitorConfig config, List<string> errors, List<string> warnings)
        {
            if (!config.EnableAIAnalysis) return;

            List<string> providers = config.GetAiAnalysisProviderNames();
            if (providers.Count == 0)
            {
                Fail(errors, "AIAnalysisProviders must include at least one provider when EnableAIAnalysis is true.");
                return;
            }

            ValidateAiAnalysisProviderMaps(config, providers, errors, warnings);

            foreach (string providerName in providers)
            {
                AiAnalysisProviderSettings settings = config.AiAnalysisSettingsFor(providerName);
                if (!IsAiAnalysisProvider(settings.ProviderType))
                {
                    Fail(errors, "AIAnalysisProviders contains unsupported provider: " + providerName);
                    continue;
                }

                if (settings.ProviderType.Equals("Disabled", StringComparison.OrdinalIgnoreCase))
                {
                    Warn(warnings, "EnableAIAnalysis is true but AI provider is disabled: " + providerName);
                    continue;
                }

                if (String.IsNullOrWhiteSpace(settings.Model))
                {
                    Fail(errors, "AI analysis model must be configured for provider " + providerName + " using AIAnalysisModel or AIAnalysisProviderModels.");
                }

                if (String.IsNullOrWhiteSpace(settings.ApiUrl))
                {
                    Fail(errors, "AI analysis API URL must be configured for provider " + providerName + " using AIAnalysisApiUrl or AIAnalysisProviderApiUrls.");
                }

                if (!String.IsNullOrWhiteSpace(settings.AuthHeaderName) &&
                    String.IsNullOrWhiteSpace(settings.ApiKeyEnvironmentVariable))
                {
                    Fail(errors, "AI analysis API key environment variable must be configured for provider " + providerName + " when its auth header is not empty.");
                }

                if (settings.ProviderType.Equals("Anthropic", StringComparison.OrdinalIgnoreCase))
                {
                    if (String.IsNullOrWhiteSpace(settings.VersionHeaderName))
                    {
                        Fail(errors, "Anthropic provider " + providerName + " requires an AIAnalysisProviderVersionHeaderNames entry or default.");
                    }

                    if (String.IsNullOrWhiteSpace(settings.VersionHeaderValue))
                    {
                        Fail(errors, "Anthropic provider " + providerName + " requires an AIAnalysisProviderVersionHeaderValues entry or default.");
                    }
                }
            }
        }

        private static void ValidateAiAnalysisProviderMaps(MonitorConfig config, List<string> providers, List<string> errors, List<string> warnings)
        {
            ValidateAiAnalysisProviderMapKeys(config.AIAnalysisProviderTypes, "AIAnalysisProviderTypes", providers, warnings);
            ValidateAiAnalysisProviderMapKeys(config.AIAnalysisProviderModels, "AIAnalysisProviderModels", providers, warnings);
            ValidateAiAnalysisProviderMapKeys(config.AIAnalysisProviderApiUrls, "AIAnalysisProviderApiUrls", providers, warnings);
            ValidateAiAnalysisProviderMapKeys(config.AIAnalysisProviderApiKeyEnvironmentVariables, "AIAnalysisProviderApiKeyEnvironmentVariables", providers, warnings);
            ValidateAiAnalysisProviderMapKeys(config.AIAnalysisProviderAuthHeaderNames, "AIAnalysisProviderAuthHeaderNames", providers, warnings);
            ValidateAiAnalysisProviderMapKeys(config.AIAnalysisProviderAuthHeaderPrefixes, "AIAnalysisProviderAuthHeaderPrefixes", providers, warnings);
            ValidateAiAnalysisProviderMapKeys(config.AIAnalysisProviderVersionHeaderNames, "AIAnalysisProviderVersionHeaderNames", providers, warnings);
            ValidateAiAnalysisProviderMapKeys(config.AIAnalysisProviderVersionHeaderValues, "AIAnalysisProviderVersionHeaderValues", providers, warnings);
            ValidateAiAnalysisProviderTypeValues(config.AIAnalysisProviderTypes, providers, errors, warnings);
            ValidateDuplicateAiAnalysisProviders(providers, warnings);

            if (providers.Count <= 1) return;

            WarnIfMultiProviderGlobalConfigured(config.AIAnalysisModel, "AIAnalysisModel", "AIAnalysisProviderModels", warnings);
            WarnIfMultiProviderGlobalConfigured(config.AIAnalysisApiUrl, "AIAnalysisApiUrl", "AIAnalysisProviderApiUrls", warnings);
            WarnIfMultiProviderGlobalConfigured(config.AIAnalysisApiKeyEnvironmentVariable, "AIAnalysisApiKeyEnvironmentVariable", "AIAnalysisProviderApiKeyEnvironmentVariables", warnings);
            WarnIfMultiProviderGlobalConfigured(config.AIAnalysisAuthHeaderName, "AIAnalysisAuthHeaderName", "AIAnalysisProviderAuthHeaderNames", warnings);
            WarnIfMultiProviderGlobalConfigured(config.AIAnalysisAuthHeaderPrefix, "AIAnalysisAuthHeaderPrefix", "AIAnalysisProviderAuthHeaderPrefixes", warnings);
        }

        private static void ValidateAiAnalysisProviderMapKeys(Dictionary<string, string> map, string configKey, List<string> providers, List<string> warnings)
        {
            if (map == null) return;

            foreach (KeyValuePair<string, string> item in map)
            {
                if (String.IsNullOrWhiteSpace(item.Key)) continue;
                if (!AiAnalysisProviderConfigured(providers, item.Key))
                {
                    Warn(warnings, configKey + " targets provider that is not enabled in AIAnalysisProviders: " + item.Key);
                }
            }
        }

        private static void ValidateAiAnalysisProviderTypeValues(Dictionary<string, string> providerTypes, List<string> providers, List<string> errors, List<string> warnings)
        {
            if (providerTypes == null) return;

            foreach (KeyValuePair<string, string> item in providerTypes)
            {
                if (!AiAnalysisProviderConfigured(providers, item.Key)) continue;

                if (String.IsNullOrWhiteSpace(item.Value))
                {
                    Warn(warnings, "AIAnalysisProviderTypes entry is empty; provider name will be used as the type: " + item.Key);
                }
                else if (!IsAiAnalysisProvider(item.Value))
                {
                    Fail(errors, "AIAnalysisProviderTypes contains unsupported provider type: " + item.Key + "=" + item.Value);
                }
            }
        }

        private static void ValidateDuplicateAiAnalysisProviders(List<string> providers, List<string> warnings)
        {
            HashSet<string> seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (string provider in providers)
            {
                string canonical = MonitorConfig.CanonicalAiAnalysisProvider(provider);
                if (String.IsNullOrWhiteSpace(canonical)) continue;
                if (seen.Contains(canonical))
                {
                    Warn(warnings, "AIAnalysisProviders contains multiple entries with the same provider identity: " + provider);
                }
                else
                {
                    seen.Add(canonical);
                }
            }
        }

        private static void WarnIfMultiProviderGlobalConfigured(string value, string globalKey, string mapKey, List<string> warnings)
        {
            if (String.IsNullOrWhiteSpace(value)) return;
            Warn(warnings, globalKey + " is ignored when multiple AIAnalysisProviders are configured; use " + mapKey + " instead.");
        }

        private static void ValidateDailyReportConfig(MonitorConfig config, List<string> errors, List<string> warnings)
        {
            foreach (string destination in config.DailyReportDestinations)
            {
                if (!IsDailyReportDestination(destination))
                {
                    Warn(warnings, "DailyReportDestinations contains an unknown destination: " + destination);
                }
            }

            if (config.DailyReportCriticalCalloutRows <= 0) Fail(errors, "DailyReportCriticalCalloutRows must be greater than zero.");
            if (config.DailyReportHighSignalRows <= 0) Fail(errors, "DailyReportHighSignalRows must be greater than zero.");
            if (config.DailyReportBucketRows <= 0) Fail(errors, "DailyReportBucketRows must be greater than zero.");
            if (config.DailyReportAgentBucketRows <= 0) Fail(errors, "DailyReportAgentBucketRows must be greater than zero.");

            foreach (string section in config.DailyReportSections)
            {
                if (!IsDailyReportSection(section))
                {
                    Warn(warnings, "DailyReportSections contains an unknown section: " + section);
                }
            }

            if (config.DailyReportDestinationEnabled("Webhook"))
            {
                if (String.IsNullOrWhiteSpace(config.DailyReportWebhookUrl))
                {
                    Fail(errors, "DailyReportWebhookUrl must be configured when DailyReportDestinations includes Webhook.");
                }

                if (config.DailyReportWebhookTimeoutSeconds <= 0)
                {
                    Fail(errors, "DailyReportWebhookTimeoutSeconds must be greater than zero when daily report webhook delivery is enabled.");
                }
            }

            if (!config.EnableDailyReportArchive) return;

            if (!config.DailyReportDestinationEnabled("LocalArchive"))
            {
                Warn(warnings, "EnableDailyReportArchive is true but DailyReportDestinations does not include LocalArchive.");
            }

            if (String.IsNullOrWhiteSpace(config.DailyReportArchiveDirectory))
            {
                Fail(errors, "DailyReportArchiveDirectory must be configured when EnableDailyReportArchive is enabled.");
            }

            foreach (string format in config.DailyReportArchiveFormats)
            {
                if (!IsDailyReportArchiveFormat(format))
                {
                    Warn(warnings, "DailyReportArchiveFormats contains an unknown format: " + format);
                }
            }

        }

        private static bool IsDailyReportSection(string section)
        {
            return ProviderMatches(section, "QuickVerdict") ||
                ProviderMatches(section, "CriticalCallouts") ||
                ProviderMatches(section, "AtAGlance") ||
                ProviderMatches(section, "SignalSummary") ||
                ProviderMatches(section, "FalsePositiveContext") ||
                ProviderMatches(section, "HighSignalDetails") ||
                ProviderMatches(section, "AutomationActivity") ||
                ProviderMatches(section, "AIReview") ||
                ProviderMatches(section, "TuningNotes");
        }

        private static bool IsDailyReportDestination(string destination)
        {
            string canonical = MonitorConfig.CanonicalDailyReportDestination(destination);
            return canonical.Equals("ExternalAlertSinks", StringComparison.OrdinalIgnoreCase) ||
                canonical.Equals("LocalArchive", StringComparison.OrdinalIgnoreCase) ||
                canonical.Equals("Webhook", StringComparison.OrdinalIgnoreCase);
        }

        private static bool IsDailyReportArchiveFormat(string format)
        {
            return ProviderMatches(format, "Markdown") ||
                ProviderMatches(format, "Json");
        }

        private static void ValidateLowValueRepeatDampening(MonitorConfig config, List<string> errors, List<string> warnings)
        {
            if (!config.EnableLowValueRepeatDampening) return;

            if (config.LowValueRepeatDampeningMaximumScore < 0 || config.LowValueRepeatDampeningMaximumScore > 100)
            {
                Warn(warnings, "LowValueRepeatDampeningMaximumScore is outside the usual 0-100 range.");
            }

            if (config.LowValueRepeatDampeningWindowMinutes <= 0)
            {
                Fail(errors, "LowValueRepeatDampeningWindowMinutes must be greater than zero when repeat dampening is enabled.");
            }

            if (config.LowValueRepeatDampeningMaxExternalAlertsPerWindow <= 0)
            {
                Fail(errors, "LowValueRepeatDampeningMaxExternalAlertsPerWindow must be greater than zero when repeat dampening is enabled.");
            }

            if (config.LowValueRepeatDampeningCategories.Count == 0)
            {
                Warn(warnings, "LowValueRepeatDampeningCategories is empty; repeat dampening will not match any categories.");
            }

            foreach (string category in config.LowValueRepeatDampeningCategories)
            {
                if (!AlertRuleCatalog.IsKnownCategory(category))
                {
                    Warn(warnings, "LowValueRepeatDampeningCategories contains an unknown category: " + category);
                }
            }
        }

        private static void ValidateTermGroups(HashSet<string> groups, string configKey, List<string> warnings)
        {
            foreach (string group in groups)
            {
                if (String.IsNullOrWhiteSpace(group)) continue;
                string[] terms = group.Split('|');
                int populated = 0;
                foreach (string term in terms)
                {
                    if (!String.IsNullOrWhiteSpace(term)) populated++;
                }

                if (populated < 2)
                {
                    Warn(warnings, configKey + " entry has fewer than two terms: " + group);
                }
            }
        }

        private static void ValidateExternalAlertProviders(MonitorConfig config, List<string> errors, List<string> warnings)
        {
            bool sawProvider = false;
            foreach (string provider in config.GetExternalAlertProviders())
            {
                sawProvider = true;
                if (!IsExternalAlertProvider(provider))
                {
                    Fail(errors, "ExternalAlertProvider contains unsupported provider: " + provider);
                }
            }

            if (!sawProvider)
            {
                Warn(warnings, "ExternalAlertProvider is empty; external alerts are disabled.");
            }

            foreach (KeyValuePair<string, int> item in config.ExternalAlertProviderMinimumScores)
            {
                if (!IsExternalAlertProvider(item.Key))
                {
                    Warn(warnings, "ExternalAlertProviderMinimumScores contains an unknown provider: " + item.Key);
                }
                else if (ProviderMatches(item.Key, "Disabled"))
                {
                    Warn(warnings, "ExternalAlertProviderMinimumScores should not target disabled provider alias: " + item.Key);
                }
                else if (!ProviderEnabled(config, item.Key))
                {
                    Warn(warnings, "ExternalAlertProviderMinimumScores targets provider that is not enabled: " + item.Key);
                }

                if (item.Value < 0 || item.Value > 100)
                {
                    Warn(warnings, "ExternalAlertProviderMinimumScores entry is outside the usual 0-100 range: " + item.Key + "=" + item.Value);
                }
            }

            foreach (KeyValuePair<string, int> item in config.ExternalAlertProviderMaxPerHour)
            {
                if (!IsExternalAlertProvider(item.Key))
                {
                    Warn(warnings, "ExternalAlertProviderMaxPerHour contains an unknown provider: " + item.Key);
                }
                else if (ProviderMatches(item.Key, "Disabled"))
                {
                    Warn(warnings, "ExternalAlertProviderMaxPerHour should not target disabled provider alias: " + item.Key);
                }
                else if (!ProviderEnabled(config, item.Key))
                {
                    Warn(warnings, "ExternalAlertProviderMaxPerHour targets provider that is not enabled: " + item.Key);
                }

                if (item.Value < 0)
                {
                    Warn(warnings, "ExternalAlertProviderMaxPerHour entry must not be negative: " + item.Key + "=" + item.Value);
                }
            }

            if (ProviderEnabled(config, "LocalJsonl") && String.IsNullOrWhiteSpace(config.LocalJsonlAlertSinkFile))
            {
                Fail(errors, "LocalJsonl provider is enabled but LocalJsonlAlertSinkFile is empty.");
            }

            if (ProviderEnabled(config, "Smtp"))
            {
                if (!config.HasSmtpEmailConfig)
                {
                    Fail(errors, "SMTP provider is enabled but host, sender, or recipient settings are incomplete.");
                }
            }

            if (ProviderEnabled(config, "Webhook"))
            {
                if (String.IsNullOrWhiteSpace(config.WebhookAlertUrl))
                {
                    Fail(errors, "Webhook provider is enabled but WebhookAlertUrl is empty.");
                }
            }

            if (ProviderEnabled(config, "GenericHttpApi"))
            {
                if (String.IsNullOrWhiteSpace(config.GenericHttpApiAlertUrl))
                {
                    Fail(errors, "GenericHttpApi provider is enabled but GenericHttpApiAlertUrl is empty.");
                }
            }

            if (ProviderEnabled(config, "WindowsEventLog"))
            {
                if (String.IsNullOrWhiteSpace(config.WindowsEventLogAlertSource))
                {
                    Fail(errors, "WindowsEventLog provider is enabled but WindowsEventLogAlertSource is empty.");
                }

                if (String.IsNullOrWhiteSpace(config.WindowsEventLogAlertLogName))
                {
                    Fail(errors, "WindowsEventLog provider is enabled but WindowsEventLogAlertLogName is empty.");
                }

                try
                {
                    if (!EventLog.SourceExists(config.WindowsEventLogAlertSource))
                    {
                        Warn(warnings, "Windows Event Log source does not exist yet and will be created on first alert if the service account has permission: " + config.WindowsEventLogAlertSource);
                    }
                }
                catch (Exception ex)
                {
                    Warn(warnings, "Windows Event Log source could not be checked: " + ex.Message);
                }
            }
        }

        private static void ValidateHighSignalFileDetection(MonitorConfig config, List<string> warnings)
        {
            if (!config.EnableHighSignalFileDetection) return;

            if (!config.EnableSysmonIngestion)
            {
                Warn(warnings, "EnableHighSignalFileDetection is true but EnableSysmonIngestion is false; file-create detections will not run.");
            }

            if (config.HighRiskFilePathIndicators.Count == 0)
            {
                Warn(warnings, "HighRiskFilePathIndicators is empty; persistence-adjacent file-create detections will be limited.");
            }

            if (config.HighRiskFileExtensions.Count == 0)
            {
                Warn(warnings, "HighRiskFileExtensions is empty; executable/script file-drop detections will be limited.");
            }

            if (config.SensitiveFileNameIndicators.Count == 0 && config.AgentSecretIndicatorTerms.Count == 0)
            {
                Warn(warnings, "SensitiveFileNameIndicators and AgentSecretIndicatorTerms are empty; sensitive-file create detections will be limited.");
            }
        }

        private static void ValidateCollectorConfig(MonitorConfig config, List<string> warnings)
        {
            if (!config.EnableNetstatCollector && !config.EnableSysmonIngestion)
            {
                Warn(warnings, "EnableNetstatCollector and EnableSysmonIngestion are both false; network detections will be disabled.");
            }

            if (!config.EnableNetstatCollector &&
                !config.EnableSysmonIngestion &&
                !config.EnablePowerShellLogIngestion &&
                !config.EnableWindowsEventIngestion &&
                !config.EnablePersistenceInventory)
            {
                Warn(warnings, "All collectors are disabled; Arcane will have no telemetry to analyze.");
            }
        }

        private static void ValidateRemoteEndpointEnrichment(MonitorConfig config, List<string> errors, List<string> warnings)
        {
            if (config.RemoteEndpointEnrichmentTimeoutSeconds <= 0)
            {
                Fail(errors, "RemoteEndpointEnrichmentTimeoutSeconds must be greater than zero.");
            }

            if (config.RemoteEndpointEnrichmentCacheMinutes < 0)
            {
                Fail(errors, "RemoteEndpointEnrichmentCacheMinutes must not be negative.");
            }

            if (config.RemoteEndpointRdapMaxLookupsPerPoll < 0)
            {
                Fail(errors, "RemoteEndpointRdapMaxLookupsPerPoll must not be negative.");
            }

            if (config.RemoteEndpointGeoProviderMaxLookupsPerPoll < 0)
            {
                Fail(errors, "RemoteEndpointGeoProviderMaxLookupsPerPoll must not be negative.");
            }

            foreach (string country in config.AllowedRemoteCountries)
            {
                if (!IsTwoLetterCountryCode(country))
                {
                    Fail(errors, "allowlists.allowed_remote_countries contains an invalid country code: " + country);
                }
            }

            if (config.EnableRemoteEndpointCountryBlockEnrichment &&
                (String.IsNullOrWhiteSpace(config.RemoteEndpointCountryBlocksDirectory) ||
                    !Directory.Exists(config.RemoteEndpointCountryBlocksDirectory)))
            {
                Fail(errors, "RemoteEndpointCountryBlocksDirectory not found: " + config.RemoteEndpointCountryBlocksDirectory);
            }

            if (config.EnableRemoteEndpointIpApiGeolocation)
            {
                ValidateRemoteEndpointUrlTemplate(config.RemoteEndpointIpApiUrlTemplate, "RemoteEndpointIpApiUrlTemplate", errors);
            }

            if (config.EnableRemoteEndpointIpWhoisGeolocation)
            {
                ValidateRemoteEndpointUrlTemplate(config.RemoteEndpointIpWhoisUrlTemplate, "RemoteEndpointIpWhoisUrlTemplate", errors);
            }

            if (config.EnableRemoteEndpointRdapEnrichment &&
                String.IsNullOrWhiteSpace(config.RemoteEndpointRdapUrlTemplate))
            {
                Fail(errors, "RemoteEndpointRdapUrlTemplate must be configured when EnableRemoteEndpointRdapEnrichment is true.");
            }

            ValidateRemoteEndpointPolicy(config, errors, warnings);
        }

        private static bool IsTwoLetterCountryCode(string value)
        {
            if (String.IsNullOrWhiteSpace(value) || value.Length != 2) return false;
            return Char.IsLetter(value[0]) && Char.IsLetter(value[1]);
        }

        private static void ValidateRemoteEndpointPolicy(MonitorConfig config, List<string> errors, List<string> warnings)
        {
            if (!config.EnableRemoteEndpointPolicy) return;

            if (String.IsNullOrWhiteSpace(config.PolicyFile))
            {
                Fail(errors, "PolicyFile must be configured when EnableRemoteEndpointPolicy is true.");
                return;
            }

            RemoteEndpointPolicy policy = RemoteEndpointPolicy.Load(config.RemoteEndpointPolicyFile);
            if (!policy.FileFound)
            {
                Fail(errors, "Unified policy file not found: " + config.PolicyFile);
                return;
            }

            foreach (string error in policy.Errors)
            {
                Fail(errors, error);
            }

            foreach (string warning in policy.Warnings)
            {
                Warn(warnings, warning);
            }

            if (!config.EnableRemoteEndpointEnrichment)
            {
                Warn(warnings, "Remote endpoint policy is enabled but EnableRemoteEndpointEnrichment is false; owner, domain, and country matching will be limited.");
            }

            bool hasCountrySource =
                config.EnableRemoteEndpointRdapEnrichment ||
                config.EnableRemoteEndpointCountryBlockEnrichment ||
                config.EnableRemoteEndpointIpApiGeolocation ||
                config.EnableRemoteEndpointIpWhoisGeolocation;

            if (policy.HasCountryCriteria && !hasCountrySource)
            {
                Warn(warnings, "Remote endpoint policy contains country criteria but all remote country enrichment sources are disabled; country matching will not be available.");
            }

            bool hasOwnerSource =
                config.EnableRemoteEndpointRdapEnrichment ||
                config.EnableRemoteEndpointIpApiGeolocation ||
                config.EnableRemoteEndpointIpWhoisGeolocation;

            if (policy.HasOwnerCriteria && !hasOwnerSource)
            {
                Warn(warnings, "Remote endpoint policy contains owner/ASN criteria but all remote owner/ASN enrichment sources are disabled; owner/ASN matching will not be available.");
            }

            if (policy.Errors.Count == 0)
            {
                Pass("Remote endpoint policy parsed: " + policy.Rules.Count.ToString(System.Globalization.CultureInfo.InvariantCulture) + " entries from " + config.PolicyFile);
            }
        }

        private static void ValidateRemoteEndpointUrlTemplate(string template, string key, List<string> errors)
        {
            if (String.IsNullOrWhiteSpace(template))
            {
                Fail(errors, key + " must be configured when its provider is enabled.");
                return;
            }

            if (template.IndexOf("{ip}", StringComparison.OrdinalIgnoreCase) < 0)
            {
                Fail(errors, key + " must contain the {ip} placeholder.");
            }
        }

        private static void ValidateAgentProfile(MonitorConfig config, List<string> warnings)
        {
            if (!config.EnableAgentProfile) return;

            if (config.AgentProcessNames.Count == 0)
            {
                Warn(warnings, "EnableAgentProfile is true but AgentProcessNames is empty; agent-context labels will be limited.");
            }

            if (config.AgentChildProcessNames.Count == 0)
            {
                Warn(warnings, "EnableAgentProfile is true but AgentChildProcessNames is empty; child shell/package-tool correlation will be limited.");
            }

            if (config.EnableAgentAdminCommandGuardrails)
            {
                if (config.AgentAdminCommandTerms.Count == 0)
                {
                    Warn(warnings, "EnableAgentAdminCommandGuardrails is true but AgentAdminCommandTerms is empty; agent admin-command guardrails will not match.");
                }

                if (config.AgentAdminCommandMinimumScore < 0 || config.AgentAdminCommandMinimumScore > 100)
                {
                    Warn(warnings, "AgentAdminCommandMinimumScore is outside the usual 0-100 range.");
                }

                if (config.AgentApprovedAdminTaskNames.Count == 0)
                {
                    Warn(warnings, "EnableAgentAdminCommandGuardrails is true but AgentApprovedAdminTaskNames is empty; expected admin bridge activity may require local tuning.");
                }
            }

            if (config.EnableAgentSecretReferenceGuardrails)
            {
                if (config.AgentSecretReferenceTerms.Count == 0 && config.AgentSecretIndicatorTerms.Count == 0)
                {
                    Warn(warnings, "EnableAgentSecretReferenceGuardrails is true but AgentSecretReferenceTerms and AgentSecretIndicatorTerms are empty; secret-reference guardrails will not match.");
                }

                if (config.AgentSecretReferenceMinimumScore < 0 || config.AgentSecretReferenceMinimumScore > 100)
                {
                    Warn(warnings, "AgentSecretReferenceMinimumScore is outside the usual 0-100 range.");
                }
            }

            if (config.EnableAgentSupplyChainGuardrails)
            {
                if (config.AgentSupplyChainTerms.Count == 0)
                {
                    Warn(warnings, "EnableAgentSupplyChainGuardrails is true but AgentSupplyChainTerms is empty; package/download guardrails will not match.");
                }

                if (config.AgentSupplyChainMinimumScore < 0 || config.AgentSupplyChainMinimumScore > 100)
                {
                    Warn(warnings, "AgentSupplyChainMinimumScore is outside the usual 0-100 range.");
                }
            }
        }

        private static void ValidateAgentActivityLedger(MonitorConfig config, List<string> errors, List<string> warnings)
        {
            if (!config.EnableAgentActivityLedger) return;

            if (!config.EnableAgentProfile)
            {
                Warn(warnings, "EnableAgentActivityLedger is true but EnableAgentProfile is false; no agent-involved alerts will be recorded.");
            }

            if (String.IsNullOrWhiteSpace(config.AgentActivityLedgerFile))
            {
                Fail(errors, "AgentActivityLedgerFile must be configured when agent activity ledger is enabled.");
            }

            if (config.AgentActivityLedgerMinimumScore < 0 || config.AgentActivityLedgerMinimumScore > 100)
            {
                Warn(warnings, "AgentActivityLedgerMinimumScore is outside the usual 0-100 range.");
            }
        }

        private static void ValidateMaintenanceSessionMarkers(MonitorConfig config, List<string> errors, List<string> warnings)
        {
            if (!config.EnableMaintenanceSessionMarkers) return;

            if (!config.EnableMaintenanceContext)
            {
                Warn(warnings, "EnableMaintenanceSessionMarkers is true but EnableMaintenanceContext is false; markers will not annotate alerts.");
            }

            if (String.IsNullOrWhiteSpace(config.MaintenanceSessionMarkerFile))
            {
                Fail(errors, "MaintenanceSessionMarkerFile must be configured when maintenance session markers are enabled.");
            }

            if (config.MaintenanceSessionDefaultMinutes <= 0)
            {
                Fail(errors, "MaintenanceSessionDefaultMinutes must be greater than zero.");
            }

            if (config.MaintenanceSessionMaximumMinutes <= 0)
            {
                Fail(errors, "MaintenanceSessionMaximumMinutes must be greater than zero.");
            }

            if (config.MaintenanceSessionDefaultMinutes > config.MaintenanceSessionMaximumMinutes)
            {
                Warn(warnings, "MaintenanceSessionDefaultMinutes is greater than MaintenanceSessionMaximumMinutes; requested default sessions will be capped.");
            }
        }

        private static void ValidateResponseConfig(MonitorConfig config, List<string> errors, List<string> warnings)
        {
            if (!IsResponseMode(config.ResponseMode))
            {
                Fail(errors, "ResponseMode must be AlertOnly, DryRunBlockRemoteIp, DryRunTerminateProcess, DryRunBlockAndTerminate, BlockRemoteIp, TerminateProcess, or BlockAndTerminate.");
            }

            if (config.ResponseMinimumScore < 0 || config.ResponseMinimumScore > 100)
            {
                Warn(warnings, "ResponseMinimumScore is outside the usual 0-100 range.");
            }

            if (IsFirewallResponseMode(config.ResponseMode) && !config.EnableFirewallBlockResponse)
            {
                Fail(errors, "BlockRemoteIp and BlockAndTerminate require EnableFirewallBlockResponse=true. Use a DryRun* mode unless firewall blocking is intentional.");
            }

            if (IsTerminateResponseMode(config.ResponseMode) && !config.EnableProcessTerminationResponse)
            {
                Fail(errors, "TerminateProcess and BlockAndTerminate require EnableProcessTerminationResponse=true. Process termination cannot be rolled back.");
            }

            if (IsActiveResponseMode(config.ResponseMode) && config.ResponseMinimumScore < 90)
            {
                Warn(warnings, "ResponseMinimumScore is below 90 while an active response mode is enabled.");
            }

            if (IsDryRunResponseMode(config.ResponseMode) && config.ResponseMinimumScore < 60)
            {
                Warn(warnings, "ResponseMinimumScore is below 60 while response dry-run is enabled; the ledger may become noisy.");
            }

            if (config.EnableResponseLedger && String.IsNullOrWhiteSpace(config.ResponseLedgerFile))
            {
                Fail(errors, "ResponseLedgerFile must be configured when response ledger is enabled.");
            }

            if (IsActiveResponseMode(config.ResponseMode) && !config.EnableResponseLedger)
            {
                Fail(errors, "Active response requires EnableResponseLedger=true so actions are auditable and firewall blocks can be reviewed.");
            }

            ValidateResponsePolicy(config, warnings);

            if (IsDryRunResponseMode(config.ResponseMode) && !config.EnableResponseLedger)
            {
                Warn(warnings, "Response dry-run mode is enabled but EnableResponseLedger is false; intended actions will only appear in the service log.");
            }

            if (config.EnableResponseFollowUpDetections)
            {
                if (!config.EnableResponseLedger)
                {
                    Warn(warnings, "EnableResponseFollowUpDetections is true but EnableResponseLedger is false; response follow-up detections will be limited.");
                }

                if (config.ResponseProcessRespawnWindowMinutes <= 0)
                {
                    Fail(errors, "ResponseProcessRespawnWindowMinutes must be greater than zero when response follow-up detections are enabled.");
                }

                if (config.ResponseProcessRespawnMinimumScore < 0 || config.ResponseProcessRespawnMinimumScore > 100)
                {
                    Warn(warnings, "ResponseProcessRespawnMinimumScore is outside the usual 0-100 range.");
                }
            }

            if (config.ResponseFollowUpExternalAlertMinimumScore < 0 || config.ResponseFollowUpExternalAlertMinimumScore > 100)
            {
                Warn(warnings, "ResponseFollowUpExternalAlertMinimumScore is outside the usual 0-100 range.");
            }
        }

        private static void ValidateResponsePolicy(MonitorConfig config, List<string> warnings)
        {
            foreach (string category in config.ResponseAllowedCategories)
            {
                if (!AlertRuleCatalog.IsKnownCategory(category))
                {
                    Warn(warnings, "response_policy.allowed_categories contains an unknown category: " + category);
                }
            }

            foreach (string category in config.ResponseBlockedCategories)
            {
                if (!AlertRuleCatalog.IsKnownCategory(category))
                {
                    Warn(warnings, "response_policy.blocked_categories contains an unknown category: " + category);
                }
            }

            if (!IsActiveResponseMode(config.ResponseMode)) return;

            if (!config.EnableResponsePolicy)
            {
                Warn(warnings, "Active response is enabled while EnableResponsePolicy is false; actions will rely only on score, action gates, and target availability.");
            }
            else if (!HasConfiguredValues(config.ResponseAllowedRuleIds) &&
                !HasConfiguredValues(config.ResponseAllowedCategories))
            {
                Warn(warnings, "Active response is enabled but response_policy.allowed_rule_ids and response_policy.allowed_categories are empty in PolicyFile; response policy will skip all active actions.");
            }

            if (IsTerminateResponseMode(config.ResponseMode) &&
                !HasConfiguredValues(config.ResponseProtectedProcessNames))
            {
                Warn(warnings, "Process termination response is enabled but response_policy.protected_process_names is empty in PolicyFile.");
            }
        }

        private static void ValidateLogDirectory(MonitorConfig config, List<string> errors)
        {
            try
            {
                Directory.CreateDirectory(config.LogDirectory);
                string path = Path.Combine(config.LogDirectory, ".arcane-edr-validate.tmp");
                File.WriteAllText(path, DateTime.UtcNow.ToString("o"));
                File.Delete(path);
                Pass("Log directory writable: " + config.LogDirectory);
            }
            catch (Exception ex)
            {
                Fail(errors, "Log directory is not writable: " + config.LogDirectory + " (" + ex.Message + ")");
            }
        }

        private static void ValidateSecrets(MonitorConfig config, List<string> errors, List<string> warnings)
        {
            ISecretProvider secrets = new EnvironmentSecretProvider();

            if (ProviderEnabled(config, "Brevo"))
            {
                if (!config.HasBrevoEmailConfig)
                {
                    Fail(errors, "Brevo provider is enabled but sender/recipient/API settings are incomplete.");
                }

                if (String.IsNullOrWhiteSpace(secrets.GetSecret(config.BrevoApiKeyEnvironmentVariable)))
                {
                    if (config.RequireExternalAlerting)
                    {
                        Fail(errors, "Brevo API key environment variable is not visible: " + config.BrevoApiKeyEnvironmentVariable);
                    }
                    else
                    {
                        Warn(warnings, "Brevo API key environment variable is not visible: " + config.BrevoApiKeyEnvironmentVariable);
                    }
                }
                else
                {
                    Pass("Brevo API key is visible via environment variable: " + config.BrevoApiKeyEnvironmentVariable);
                }
            }

            if (ProviderEnabled(config, "Smtp") &&
                !String.IsNullOrWhiteSpace(config.SmtpPasswordEnvironmentVariable))
            {
                if (String.IsNullOrWhiteSpace(secrets.GetSecret(config.SmtpPasswordEnvironmentVariable)))
                {
                    if (config.RequireExternalAlerting)
                    {
                        Fail(errors, "SMTP password environment variable is not visible: " + config.SmtpPasswordEnvironmentVariable);
                    }
                    else
                    {
                        Warn(warnings, "SMTP password environment variable is not visible: " + config.SmtpPasswordEnvironmentVariable);
                    }
                }
                else
                {
                    Pass("SMTP password is visible via environment variable: " + config.SmtpPasswordEnvironmentVariable);
                }
            }

            if (ProviderEnabled(config, "Webhook") &&
                !String.IsNullOrWhiteSpace(config.WebhookSecretEnvironmentVariable))
            {
                if (String.IsNullOrWhiteSpace(secrets.GetSecret(config.WebhookSecretEnvironmentVariable)))
                {
                    if (config.RequireExternalAlerting)
                    {
                        Fail(errors, "Webhook secret environment variable is not visible: " + config.WebhookSecretEnvironmentVariable);
                    }
                    else
                    {
                        Warn(warnings, "Webhook secret environment variable is not visible: " + config.WebhookSecretEnvironmentVariable);
                    }
                }
                else
                {
                    Pass("Webhook secret is visible via environment variable: " + config.WebhookSecretEnvironmentVariable);
                }
            }

            if (ProviderEnabled(config, "GenericHttpApi") &&
                !String.IsNullOrWhiteSpace(config.GenericHttpApiSecretEnvironmentVariable))
            {
                if (String.IsNullOrWhiteSpace(secrets.GetSecret(config.GenericHttpApiSecretEnvironmentVariable)))
                {
                    if (config.RequireExternalAlerting)
                    {
                        Fail(errors, "Generic HTTP API secret environment variable is not visible: " + config.GenericHttpApiSecretEnvironmentVariable);
                    }
                    else
                    {
                        Warn(warnings, "Generic HTTP API secret environment variable is not visible: " + config.GenericHttpApiSecretEnvironmentVariable);
                    }
                }
                else
                {
                    Pass("Generic HTTP API secret is visible via environment variable: " + config.GenericHttpApiSecretEnvironmentVariable);
                }
            }

            if (config.DailyReportDestinationEnabled("Webhook") &&
                !String.IsNullOrWhiteSpace(config.DailyReportWebhookSecretEnvironmentVariable))
            {
                if (String.IsNullOrWhiteSpace(secrets.GetSecret(config.DailyReportWebhookSecretEnvironmentVariable)))
                {
                    Warn(warnings, "Daily report webhook secret environment variable is not visible: " + config.DailyReportWebhookSecretEnvironmentVariable);
                }
                else
                {
                    Pass("Daily report webhook secret is visible via environment variable: " + config.DailyReportWebhookSecretEnvironmentVariable);
                }
            }

            if (config.EnableAIAnalysis)
            {
                foreach (string providerName in config.GetAiAnalysisProviderNames())
                {
                    AiAnalysisProviderSettings settings = config.AiAnalysisSettingsFor(providerName);
                    if (String.IsNullOrWhiteSpace(settings.AuthHeaderName))
                    {
                        Pass("AI analysis auth header disabled by config for provider: " + providerName);
                    }
                    else if (String.IsNullOrWhiteSpace(secrets.GetSecret(settings.ApiKeyEnvironmentVariable)))
                    {
                        Warn(warnings, "AI analysis API key environment variable is not visible for provider " + providerName + ": " + settings.ApiKeyEnvironmentVariable);
                    }
                    else
                    {
                        Pass("AI analysis API key is visible for provider " + providerName + " via environment variable: " + settings.ApiKeyEnvironmentVariable);
                    }
                }
            }
        }

        private static void ValidateEventLogAccess(MonitorConfig config, List<string> warnings)
        {
            if (config.EnablePowerShellLogIngestion)
            {
                ProbeEventLog(config.PowerShellEventLogName, warnings);
            }

            if (config.EnableWindowsEventIngestion)
            {
                ProbeEventLog(config.WindowsSecurityEventLogName, warnings);
                ProbeEventLog(config.WindowsSystemEventLogName, warnings);
            }
        }

        private static void ProbeEventLog(string logName, List<string> warnings)
        {
            try
            {
                EventLogQuery query = new EventLogQuery(logName, PathType.LogName, "*[System[TimeCreated[timediff(@SystemTime) <= 600000]]]");
                using (EventLogReader reader = new EventLogReader(query))
                {
                    EventRecord record = reader.ReadEvent();
                    if (record != null) record.Dispose();
                }

                Pass("Event log readable: " + logName);
            }
            catch (Exception ex)
            {
                Warn(warnings, "Event log not readable in this context: " + logName + " (" + ex.Message + ")");
            }
        }

        private static void ValidateSysmon(MonitorConfig config, List<string> warnings)
        {
            if (!config.EnableSysmonIngestion) return;

            try
            {
                ServiceController controller = new ServiceController(config.SysmonServiceName);
                ServiceControllerStatus status = controller.Status;
                Pass(config.SysmonServiceName + " service status: " + status);
            }
            catch (Exception ex)
            {
                Warn(warnings, config.SysmonServiceName + " service not found or unreadable: " + ex.Message);
            }

            ProbeEventLog(config.SysmonEventLogName, warnings);
        }

        private static void ValidateCustomRules(MonitorConfig config, List<string> errors, List<string> warnings)
        {
            if (!config.EnableCustomRules) return;

            try
            {
                if (!File.Exists(config.CustomRulesFile))
                {
                    Warn(warnings, "Custom rules file does not exist: " + config.CustomRulesFile);
                    return;
                }

                List<CustomDetectionRule> rules = CustomRuleEngine.LoadRules(config.CustomRulesFile);
                Pass("Custom rules parsed: " + rules.Count + " rules from " + config.CustomRulesFile);
            }
            catch (Exception ex)
            {
                Fail(errors, "Custom rules file failed to parse: " + config.CustomRulesFile + " (" + ex.Message + ")");
            }
        }

        private static void ValidateDetectionPolicy(MonitorConfig config, List<string> errors, List<string> warnings)
        {
            if (!config.EnableDetectionPolicy) return;

            if (String.IsNullOrWhiteSpace(config.PolicyFile))
            {
                Fail(errors, "PolicyFile must be configured when EnableDetectionPolicy is enabled.");
                return;
            }

            DetectionPolicy policy = DetectionPolicy.Load(config.DetectionPolicyFile);
            if (!policy.FileFound)
            {
                Fail(errors, "Unified policy file not found: " + config.PolicyFile);
                return;
            }

            foreach (string error in policy.Errors)
            {
                Fail(errors, error);
            }

            foreach (string warning in policy.Warnings)
            {
                Warn(warnings, warning);
            }

            if (policy.Errors.Count == 0)
            {
                Pass("Detection policy parsed: " + policy.Rules.Count.ToString(System.Globalization.CultureInfo.InvariantCulture) + " entries from " + config.PolicyFile);
            }
        }

        private static void ValidateUnifiedPolicyFile(MonitorConfig config, List<string> errors)
        {
            if (String.IsNullOrWhiteSpace(config.PolicyFile))
            {
                Fail(errors, "PolicyFile must be configured.");
                return;
            }

            if ((config.EnableDetectionPolicy || config.EnableRemoteEndpointPolicy || config.EnableResponsePolicy) &&
                !File.Exists(config.PolicyFile))
            {
                Fail(errors, "Unified policy file not found: " + config.PolicyFile);
            }
        }

        private static bool IsResponseMode(string value)
        {
            return String.Equals(value, "AlertOnly", StringComparison.OrdinalIgnoreCase) ||
                IsDryRunResponseMode(value) ||
                IsActiveResponseMode(value);
        }

        private static bool IsDryRunResponseMode(string value)
        {
            return String.Equals(value, "DryRunBlockRemoteIp", StringComparison.OrdinalIgnoreCase) ||
                String.Equals(value, "DryRunTerminateProcess", StringComparison.OrdinalIgnoreCase) ||
                String.Equals(value, "DryRunBlockAndTerminate", StringComparison.OrdinalIgnoreCase);
        }

        private static bool IsActiveResponseMode(string value)
        {
            return String.Equals(value, "BlockRemoteIp", StringComparison.OrdinalIgnoreCase) ||
                String.Equals(value, "TerminateProcess", StringComparison.OrdinalIgnoreCase) ||
                String.Equals(value, "BlockAndTerminate", StringComparison.OrdinalIgnoreCase);
        }

        private static bool IsTerminateResponseMode(string value)
        {
            return String.Equals(value, "TerminateProcess", StringComparison.OrdinalIgnoreCase) ||
                String.Equals(value, "BlockAndTerminate", StringComparison.OrdinalIgnoreCase);
        }

        private static bool IsFirewallResponseMode(string value)
        {
            return String.Equals(value, "BlockRemoteIp", StringComparison.OrdinalIgnoreCase) ||
                String.Equals(value, "BlockAndTerminate", StringComparison.OrdinalIgnoreCase);
        }

        private static bool HasConfiguredValues(HashSet<string> values)
        {
            if (values == null) return false;
            foreach (string value in values)
            {
                if (!String.IsNullOrWhiteSpace(value)) return true;
            }

            return false;
        }

        private static void ValidateRemovedConfigKeys(MonitorConfig config, List<string> errors)
        {
            if (config == null || String.IsNullOrWhiteSpace(config.ConfigPath) || !File.Exists(config.ConfigPath)) return;

            HashSet<string> keys = ReadConfigKeys(config.ConfigPath);
            string[] removed = new[]
            {
                "DetectionPolicyFile",
                "RemoteEndpointPolicyFile",
                "AllowedListeningPorts",
                "AllowedOutboundPorts",
                "ProcessAllowedOutboundPorts",
                "TrustedProcesses",
                "BlockedDomains",
                "BlockedHashes",
                "AllowedDnsResolvers",
                "TrustedPersistenceNamePrefixes",
                "TrustedPersistencePathIndicators",
                "TrustedPersistenceSignerSubjects",
                "ResponseAllowedRuleIds",
                "ResponseAllowedCategories",
                "ResponseBlockedRuleIds",
                "ResponseBlockedCategories",
                "ResponseProtectedProcessNames",
                "AllowedRemoteCidrs",
                "BlockedRemoteCidrs",
                "TrustedRemoteOwnerPatterns",
                "BlockedRemoteOwnerPatterns",
                "TrustedRemoteDomainPatterns",
                "BlockedRemoteDomainPatterns",
                "EnableRemoteCountryPolicy",
                "AllowedRemoteCountryCodes",
                "BlockedRemoteCountryCodes",
                "RemoteCountryPolicyAlertOnUnknown",
                "RemoteCountryPolicyScore"
            };

            foreach (string key in removed)
            {
                if (keys.Contains(key))
                {
                    Fail(errors, key + " has been removed. Put allow/block/trust policy in PolicyFile instead.");
                }
            }
        }

        private static HashSet<string> ReadConfigKeys(string path)
        {
            HashSet<string> keys = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (string rawLine in File.ReadAllLines(path))
            {
                string line = rawLine.Trim();
                if (line.Length == 0 || line.StartsWith("#", StringComparison.Ordinal)) continue;

                int equals = line.IndexOf('=');
                if (equals <= 0) continue;
                string key = line.Substring(0, equals).Trim();
                if (key.Length > 0) keys.Add(key);
            }

            return keys;
        }

        private static bool ProviderEnabled(MonitorConfig config, string expectedProvider)
        {
            foreach (string provider in config.GetExternalAlertProviders())
            {
                if (ProviderMatches(provider, expectedProvider)) return true;
            }

            return false;
        }

        private static bool AiAnalysisProviderConfigured(List<string> providers, string expectedProvider)
        {
            foreach (string provider in providers)
            {
                if (provider.Equals(expectedProvider, StringComparison.OrdinalIgnoreCase)) return true;
                if (AiProviderMatches(provider, expectedProvider)) return true;
            }

            return false;
        }

        private static bool IsExternalAlertProvider(string provider)
        {
            return ProviderMatches(provider, "Disabled") ||
                ProviderMatches(provider, "None") ||
                ProviderMatches(provider, "Off") ||
                ProviderMatches(provider, "Brevo") ||
                ProviderMatches(provider, "Smtp") ||
                ProviderMatches(provider, "SmtpEmail") ||
                ProviderMatches(provider, "SmtpEmailAlertSink") ||
                ProviderMatches(provider, "Webhook") ||
                ProviderMatches(provider, "WebhookAlertSink") ||
                ProviderMatches(provider, "GenericHttpApi") ||
                ProviderMatches(provider, "GenericHttpApiAlertSink") ||
                ProviderMatches(provider, "HttpApi") ||
                ProviderMatches(provider, "LocalJsonl") ||
                ProviderMatches(provider, "LocalJsonlAlertSink") ||
                ProviderMatches(provider, "WindowsEventLog") ||
                ProviderMatches(provider, "EventLog") ||
                ProviderMatches(provider, "WindowsEventLogAlertSink");
        }

        private static bool IsAiAnalysisProvider(string provider)
        {
            return AiProviderMatches(provider, "Disabled") ||
                AiProviderMatches(provider, "None") ||
                AiProviderMatches(provider, "Off") ||
                AiProviderMatches(provider, "OpenAI") ||
                AiProviderMatches(provider, "OpenAICompatible") ||
                AiProviderMatches(provider, "OpenAIResponses") ||
                AiProviderMatches(provider, "OpenAICompatibleResponses") ||
                AiProviderMatches(provider, "Responses") ||
                AiProviderMatches(provider, "Anthropic") ||
                AiProviderMatches(provider, "Claude") ||
                AiProviderMatches(provider, "AnthropicClaude");
        }

        private static bool AiProviderMatches(string provider, string expected)
        {
            return MonitorConfig.CanonicalAiAnalysisProvider(provider).Equals(
                MonitorConfig.CanonicalAiAnalysisProvider(expected),
                StringComparison.OrdinalIgnoreCase);
        }

        private static bool ProviderMatches(string provider, string expected)
        {
            return CanonicalProvider(provider).Equals(CanonicalProvider(expected), StringComparison.OrdinalIgnoreCase);
        }

        private static string CanonicalProvider(string provider)
        {
            return MonitorConfig.CanonicalExternalAlertProvider(provider);
        }

        private static int Finish(List<string> errors, List<string> warnings)
        {
            Console.WriteLine();
            Console.WriteLine("Validation summary: " + errors.Count + " error(s), " + warnings.Count + " warning(s).");
            return errors.Count == 0 ? 0 : 1;
        }

        private static void Pass(string message)
        {
            Console.WriteLine("[PASS] " + message);
        }

        private static void Warn(List<string> warnings, string message)
        {
            warnings.Add(message);
            Console.WriteLine("[WARN] " + message);
        }

        private static void Fail(List<string> errors, string message)
        {
            errors.Add(message);
            Console.WriteLine("[FAIL] " + message);
        }
    }
}
