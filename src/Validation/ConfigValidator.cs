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
            List<string> errors = new List<string>();
            List<string> warnings = new List<string>();
            MonitorConfig config = null;

            try
            {
                config = MonitorConfig.Load(baseDirectory);
                Pass("Loaded config: " + config.ConfigPath);
            }
            catch (Exception ex)
            {
                Fail(errors, "Config load failed: " + ex.Message);
                return Finish(errors, warnings);
            }

            ValidateBasicSettings(config, errors, warnings);
            ValidateLogDirectory(config, errors);
            ValidateSecrets(config, errors, warnings);
            ValidateEventLogAccess(config, warnings);
            ValidateSysmon(config, warnings);
            ValidateCustomRules(config, errors, warnings);

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
            ValidateSuppressionGroups(config, warnings);
            if (config.BaselineLearningEmailMinimumScore < 0 || config.BaselineLearningEmailMinimumScore > 100) Warn(warnings, "BaselineLearningEmailMinimumScore is outside the usual 0-100 range.");
            if (config.OpenAIAnalysisBaselineEmailMinimumScore < 0 || config.OpenAIAnalysisBaselineEmailMinimumScore > 100) Warn(warnings, "OpenAIAnalysisBaselineEmailMinimumScore is outside the usual 0-100 range.");
            if (config.OpenAIAnalysisMinimumIncludedAlertScore < 0 || config.OpenAIAnalysisMinimumIncludedAlertScore > 100) Warn(warnings, "OpenAIAnalysisMinimumIncludedAlertScore is outside the usual 0-100 range.");
            if (config.OpenAIAnalysisBaselineMinimumIncludedAlertScore < 0 || config.OpenAIAnalysisBaselineMinimumIncludedAlertScore > 100) Warn(warnings, "OpenAIAnalysisBaselineMinimumIncludedAlertScore is outside the usual 0-100 range.");
            ValidateDailySummarySchedule(config, errors, warnings);
            if (config.MinimumEmailScore < 0 || config.MinimumEmailScore > 100) Warn(warnings, "MinimumEmailScore is outside the usual 0-100 range.");
            if (config.OpenAIAnalysisMaxChars > 20000) Warn(warnings, "OpenAIAnalysisMaxChars is above 20000; compact analysis may use more tokens than intended.");
            if (config.SmtpPort < 1 || config.SmtpPort > 65535) Fail(errors, "SmtpPort must be between 1 and 65535.");
            if (config.SmtpTimeoutSeconds <= 0) Fail(errors, "SmtpTimeoutSeconds must be greater than zero.");
            if (config.WebhookTimeoutSeconds <= 0) Fail(errors, "WebhookTimeoutSeconds must be greater than zero.");
            if (config.GenericHttpApiTimeoutSeconds <= 0) Fail(errors, "GenericHttpApiTimeoutSeconds must be greater than zero.");
            if (config.WindowsEventLogAlertEventId < 1 || config.WindowsEventLogAlertEventId > 65535) Fail(errors, "WindowsEventLogAlertEventId must be between 1 and 65535.");
            ValidateAgentProfile(config, warnings);
            if (!IsResponseMode(config.ResponseMode)) Fail(errors, "ResponseMode must be AlertOnly, BlockRemoteIp, TerminateProcess, or BlockAndTerminate.");
            if (config.ResponseMinimumScore < 90 && !config.ResponseMode.Equals("AlertOnly", StringComparison.OrdinalIgnoreCase))
            {
                Warn(warnings, "ResponseMinimumScore is below 90 while an active response mode is enabled.");
            }
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

        private static void ValidateSuppressionGroups(MonitorConfig config, List<string> warnings)
        {
            foreach (string group in config.ExternalAlertSuppressionTermGroups)
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
                    Warn(warnings, "ExternalAlertSuppressionTermGroups entry has fewer than two terms: " + group);
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

            if (config.EnableOpenAiLogAnalysis)
            {
                if (String.IsNullOrWhiteSpace(secrets.GetSecret(config.OpenAIApiKeyEnvironmentVariable)))
                {
                    Warn(warnings, "OpenAI API key environment variable is not visible: " + config.OpenAIApiKeyEnvironmentVariable);
                }
                else
                {
                    Pass("OpenAI API key is visible via environment variable: " + config.OpenAIApiKeyEnvironmentVariable);
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

        private static bool IsResponseMode(string value)
        {
            return value.Equals("AlertOnly", StringComparison.OrdinalIgnoreCase) ||
                value.Equals("BlockRemoteIp", StringComparison.OrdinalIgnoreCase) ||
                value.Equals("TerminateProcess", StringComparison.OrdinalIgnoreCase) ||
                value.Equals("BlockAndTerminate", StringComparison.OrdinalIgnoreCase);
        }

        private static bool ProviderEnabled(MonitorConfig config, string expectedProvider)
        {
            foreach (string provider in config.GetExternalAlertProviders())
            {
                if (ProviderMatches(provider, expectedProvider)) return true;
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

        private static bool ProviderMatches(string provider, string expected)
        {
            return CanonicalProvider(provider).Equals(CanonicalProvider(expected), StringComparison.OrdinalIgnoreCase);
        }

        private static string CanonicalProvider(string provider)
        {
            if (provider == null) return "";
            if (provider.Equals("None", StringComparison.OrdinalIgnoreCase) ||
                provider.Equals("Off", StringComparison.OrdinalIgnoreCase))
            {
                return "Disabled";
            }

            if (provider.Equals("SmtpEmail", StringComparison.OrdinalIgnoreCase) ||
                provider.Equals("SmtpEmailAlertSink", StringComparison.OrdinalIgnoreCase))
            {
                return "Smtp";
            }

            if (provider.Equals("WebhookAlertSink", StringComparison.OrdinalIgnoreCase))
            {
                return "Webhook";
            }

            if (provider.Equals("GenericHttpApiAlertSink", StringComparison.OrdinalIgnoreCase) ||
                provider.Equals("HttpApi", StringComparison.OrdinalIgnoreCase))
            {
                return "GenericHttpApi";
            }

            if (provider.Equals("LocalJsonlAlertSink", StringComparison.OrdinalIgnoreCase))
            {
                return "LocalJsonl";
            }

            if (provider.Equals("EventLog", StringComparison.OrdinalIgnoreCase) ||
                provider.Equals("WindowsEventLogAlertSink", StringComparison.OrdinalIgnoreCase))
            {
                return "WindowsEventLog";
            }

            return provider;
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
