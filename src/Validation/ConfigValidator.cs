using System;
using System.Collections.Generic;
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
            ValidateSuppressionGroups(config, warnings);
            if (config.BaselineLearningEmailMinimumScore < 0 || config.BaselineLearningEmailMinimumScore > 100) Warn(warnings, "BaselineLearningEmailMinimumScore is outside the usual 0-100 range.");
            if (config.OpenAIAnalysisBaselineEmailMinimumScore < 0 || config.OpenAIAnalysisBaselineEmailMinimumScore > 100) Warn(warnings, "OpenAIAnalysisBaselineEmailMinimumScore is outside the usual 0-100 range.");
            if (config.OpenAIAnalysisMinimumIncludedAlertScore < 0 || config.OpenAIAnalysisMinimumIncludedAlertScore > 100) Warn(warnings, "OpenAIAnalysisMinimumIncludedAlertScore is outside the usual 0-100 range.");
            if (config.OpenAIAnalysisBaselineMinimumIncludedAlertScore < 0 || config.OpenAIAnalysisBaselineMinimumIncludedAlertScore > 100) Warn(warnings, "OpenAIAnalysisBaselineMinimumIncludedAlertScore is outside the usual 0-100 range.");
            ValidateDailySummarySchedule(config, errors, warnings);
            if (config.MinimumEmailScore < 0 || config.MinimumEmailScore > 100) Warn(warnings, "MinimumEmailScore is outside the usual 0-100 range.");
            if (config.OpenAIAnalysisMaxChars > 20000) Warn(warnings, "OpenAIAnalysisMaxChars is above 20000; compact analysis may use more tokens than intended.");
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

            if (config.ExternalAlertProvider.Equals("Brevo", StringComparison.OrdinalIgnoreCase))
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
