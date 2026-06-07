using System;
using System.Collections.Generic;
using System.IO;
using System.Net;

namespace ArcaneEDR
{
    internal sealed class MonitorConfig
    {
        private readonly List<CidrRange> allowedRemoteCidrs = new List<CidrRange>();
        private readonly List<CidrRange> blockedRemoteCidrs = new List<CidrRange>();
        private readonly List<CidrRange> dohProviderCidrs = new List<CidrRange>();

        public string ProductName = "Arcane EDR";
        public string ServiceName = "ArcaneEDR";
        public string ServiceDisplayName = "Arcane EDR";
        public string ServiceDescription = "Monitors host, process, persistence, PowerShell, Sysmon, and network activity for suspicious behavior on unattended agent workstations.";
        public int PollIntervalSeconds = 10;
        public int AlertCooldownSeconds = 300;
        public int MinimumEmailScore = 60;
        public HashSet<string> DisabledRuleIds = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        public HashSet<string> DisabledRuleCategories = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        public Dictionary<string, int> RuleMinimumEmailScores = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        public Dictionary<string, int> CategoryMinimumEmailScores = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        public int ExternalAlertMaxPerDispatch = 3;
        public int ExternalAlertMaxPerHour = 12;
        public HashSet<string> ExternalAlertSuppressionTermGroups = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        public bool ExternalAlertRetryEnabled = true;
        public int ExternalAlertRetryIntervalSeconds = 300;
        public int ExternalAlertRetryMaxIntervalSeconds = 3600;
        public int ExternalAlertRetryMaxAttempts = 12;
        public int ExternalAlertRetryMaxQueued = 50;
        public int ExternalAlertRetryMaxPerPoll = 3;
        public string ExternalAlertRetryQueueFile = "ArcaneExternalAlertRetry.queue";
        public bool RequireExternalAlerting;
        public string LogDirectory;
        public string ConfigPath;
        public bool NotifyOnServiceStart = true;
        public bool NotifyOnServiceStop;
        public bool NotifyOnCrashRecovery = true;
        public bool EnableDailySummary = true;
        public int DailySummaryIntervalHours = 24;
        public string DailySummaryLocalTime = "08:00";
        public string DailySummaryTimeZoneId = "";
        public int DailySummaryScore = 60;
        public int HealthHeartbeatSeconds = 60;
        public bool EnableOpenAiLogAnalysis = true;
        public int OpenAIAnalysisIntervalMinutes = 60;
        public int OpenAIAnalysisScoreThreshold = 95;
        public int OpenAIAnalysisBaselineEmailMinimumScore = 95;
        public int OpenAIAnalysisMinimumIncludedAlertScore = 60;
        public int OpenAIAnalysisBaselineMinimumIncludedAlertScore = 90;
        public HashSet<string> OpenAIAnalysisExcludedRuleIds = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        public string OpenAIAnalysisModel = "gpt-5.5";
        public string OpenAIApiKeyEnvironmentVariable = "OPENAI_API_KEY";
        public int OpenAIAnalysisMaxLogLines = 80;
        public int OpenAIAnalysisMaxAlertLines = 80;
        public int OpenAIAnalysisMaxChars = 12000;
        public string OpenAIAnalysisApiUrl = "https://api.openai.com/v1/responses";
        public bool DetectEncodedCommandLines = true;
        public int EncodedCommandMinimumLength = 80;
        public string ExternalAlertProvider = "Disabled";
        public string BrevoApiUrl = "https://api.brevo.com/v3/smtp/email";
        public string BrevoApiKeyEnvironmentVariable = "BREVO_API_KEY";
        public string BrevoSenderEmail;
        public string BrevoSenderName = "Arcane EDR";
        public string BrevoRecipientEmail;
        public string BrevoRecipientName;
        public string SmtpHost;
        public int SmtpPort = 587;
        public bool SmtpEnableSsl = true;
        public int SmtpTimeoutSeconds = 15;
        public string SmtpUsername;
        public string SmtpPasswordEnvironmentVariable;
        public string SmtpSenderEmail;
        public string SmtpSenderName = "Arcane EDR";
        public string SmtpRecipientEmail;
        public string SmtpRecipientName;
        public string WebhookAlertUrl;
        public string WebhookSecretEnvironmentVariable;
        public string WebhookSecretHeaderName = "Authorization";
        public string WebhookSecretPrefix = "Bearer ";
        public int WebhookTimeoutSeconds = 15;
        public string GenericHttpApiAlertUrl;
        public string GenericHttpApiSecretEnvironmentVariable;
        public string GenericHttpApiSecretHeaderName = "Authorization";
        public string GenericHttpApiSecretPrefix = "Bearer ";
        public int GenericHttpApiTimeoutSeconds = 15;
        public string LocalJsonlAlertSinkFile = "ArcaneExternalAlerts.jsonl";
        public string WindowsEventLogAlertSource = "ArcaneEDR";
        public string WindowsEventLogAlertLogName = "Application";
        public int WindowsEventLogAlertEventId = 9100;
        public bool EnableSysmonIngestion = true;
        public string SysmonServiceName = "Sysmon";
        public string SysmonEventLogName = "Microsoft-Windows-Sysmon/Operational";
        public int SysmonLookbackMinutes = 10;
        public int SysmonMaxEventsPerPoll = 200;
        public bool EnablePowerShellLogIngestion = true;
        public string PowerShellEventLogName = "Microsoft-Windows-PowerShell/Operational";
        public int PowerShellLookbackMinutes = 10;
        public int PowerShellMaxEventsPerPoll = 200;
        public bool EnableWindowsEventIngestion = true;
        public string WindowsSecurityEventLogName = "Security";
        public string WindowsSystemEventLogName = "System";
        public int WindowsEventLookbackMinutes = 10;
        public int WindowsEventMaxEventsPerPoll = 200;
        public bool EnablePersistenceInventory = true;
        public int PersistenceInventoryIntervalMinutes = 60;
        public bool EnableReputationCache = true;
        public string ReputationCacheFile = "ArcaneReputation.tsv";
        public bool EnableCustomRules = true;
        public string CustomRulesFile = "custom-rules.json";
        public bool EnableIncidentGrouping = true;
        public string IncidentStoreFile = "ArcaneIncidents.jsonl";
        public int IncidentWindowMinutes = 30;
        public int IncidentMinimumScore = 60;
        public bool BaselineEnabled = true;
        public bool BaselineLearningMode = true;
        public int BaselineLearningEmailMinimumScore = 90;
        public int BaselineWarmupHours = 24;
        public string BaselineFile = "ArcaneBaseline.tsv";
        public string ResponseMode = "AlertOnly";
        public int ResponseMinimumScore = 95;
        public long MaxLogFileBytes = 10485760;
        public PortRuleSet AllowedListeningPorts = new PortRuleSet();
        public PortRuleSet AllowedOutboundPorts = new PortRuleSet();
        public PortRuleSet HighRiskRemotePorts = new PortRuleSet();
        public PortRuleSet LateralMovementPorts = new PortRuleSet();
        public HashSet<string> TrustedProcesses = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        public HashSet<string> LolbinProcesses = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        public HashSet<string> KnownRmmProcesses = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        public HashSet<string> SuspiciousParentProcesses = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        public HashSet<string> SuspiciousCommandLineTerms = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        public HashSet<string> BlockedDomains = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        public HashSet<string> BlockedHashes = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        public HashSet<string> DynamicDnsSuffixes = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        public HashSet<string> UserWritablePathIndicators = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        public HashSet<string> TrustedPersistencePathIndicators = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        public HashSet<string> TrustedPersistenceNamePrefixes = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        public bool EnableAgentProfile = true;
        public HashSet<string> AgentProcessNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        public HashSet<string> AgentChildProcessNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        public HashSet<string> AgentWorkspaceRoots = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        public HashSet<string> AgentPublishRoots = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        public HashSet<string> AgentPackageManagerProcesses = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        public HashSet<string> AgentApprovedAdminTaskNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        public HashSet<string> AgentSecretIndicatorTerms = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        public HashSet<IPAddress> AllowedDnsResolvers = new HashSet<IPAddress>();
        public bool EnforceAuthorizedDnsResolvers;
        public int ConnectionBurstThreshold = 25;
        public int BeaconMinimumSamples = 5;
        public int BeaconMaxAverageIntervalSeconds = 600;
        public double BeaconMaxJitterRatio = 0.25;

        public bool HasBrevoEmailConfig
        {
            get
            {
                return !String.IsNullOrWhiteSpace(BrevoApiUrl) &&
                    !String.IsNullOrWhiteSpace(BrevoApiKeyEnvironmentVariable) &&
                    !String.IsNullOrWhiteSpace(BrevoSenderEmail) &&
                    !String.IsNullOrWhiteSpace(BrevoRecipientEmail);
            }
        }

        public bool HasSmtpEmailConfig
        {
            get
            {
                return !String.IsNullOrWhiteSpace(SmtpHost) &&
                    SmtpPort > 0 &&
                    !String.IsNullOrWhiteSpace(SmtpSenderEmail) &&
                    !String.IsNullOrWhiteSpace(SmtpRecipientEmail);
            }
        }

        public static MonitorConfig Load(string baseDirectory)
        {
            string configPath = ResolveConfigPath(baseDirectory);
            Dictionary<string, string> values = ReadConfigFile(configPath);

            MonitorConfig config = new MonitorConfig();
            config.ConfigPath = configPath;
            config.ProductName = ReadString(values, "ProductName", config.ProductName);
            config.ServiceName = ReadString(values, "ServiceName", config.ServiceName);
            config.ServiceDisplayName = ReadString(values, "ServiceDisplayName", config.ServiceDisplayName);
            config.ServiceDescription = ReadString(values, "ServiceDescription", config.ServiceDescription);
            config.PollIntervalSeconds = ReadInt(values, "PollIntervalSeconds", config.PollIntervalSeconds);
            config.AlertCooldownSeconds = ReadInt(values, "AlertCooldownSeconds", config.AlertCooldownSeconds);
            config.MinimumEmailScore = ReadInt(values, "MinimumEmailScore", config.MinimumEmailScore);
            config.DisabledRuleIds = ReadStringSet(values, "DisabledRuleIds");
            config.DisabledRuleCategories = ReadStringSet(values, "DisabledRuleCategories");
            config.RuleMinimumEmailScores = ReadStringIntMap(values, "RuleMinimumEmailScores");
            config.CategoryMinimumEmailScores = ReadStringIntMap(values, "CategoryMinimumEmailScores");
            config.ExternalAlertMaxPerDispatch = ReadInt(values, "ExternalAlertMaxPerDispatch", config.ExternalAlertMaxPerDispatch);
            config.ExternalAlertMaxPerHour = ReadInt(values, "ExternalAlertMaxPerHour", config.ExternalAlertMaxPerHour);
            config.ExternalAlertSuppressionTermGroups = ReadStringSet(values, "ExternalAlertSuppressionTermGroups");
            config.RequireExternalAlerting = ReadBool(values, "RequireExternalAlerting", ReadBool(values, "RequireEmailConfig", false));
            config.LogDirectory = ResolvePath(baseDirectory, ReadString(values, "LogDirectory", "logs"));
            config.ExternalAlertRetryEnabled = ReadBool(values, "ExternalAlertRetryEnabled", config.ExternalAlertRetryEnabled);
            config.ExternalAlertRetryIntervalSeconds = ReadInt(values, "ExternalAlertRetryIntervalSeconds", config.ExternalAlertRetryIntervalSeconds);
            config.ExternalAlertRetryMaxIntervalSeconds = ReadInt(values, "ExternalAlertRetryMaxIntervalSeconds", config.ExternalAlertRetryMaxIntervalSeconds);
            config.ExternalAlertRetryMaxAttempts = ReadInt(values, "ExternalAlertRetryMaxAttempts", config.ExternalAlertRetryMaxAttempts);
            config.ExternalAlertRetryMaxQueued = ReadInt(values, "ExternalAlertRetryMaxQueued", config.ExternalAlertRetryMaxQueued);
            config.ExternalAlertRetryMaxPerPoll = ReadInt(values, "ExternalAlertRetryMaxPerPoll", config.ExternalAlertRetryMaxPerPoll);
            config.ExternalAlertRetryQueueFile = ResolvePath(config.LogDirectory, ReadString(values, "ExternalAlertRetryQueueFile", config.ExternalAlertRetryQueueFile));
            config.NotifyOnServiceStart = ReadBool(values, "NotifyOnServiceStart", config.NotifyOnServiceStart);
            config.NotifyOnServiceStop = ReadBool(values, "NotifyOnServiceStop", config.NotifyOnServiceStop);
            config.NotifyOnCrashRecovery = ReadBool(values, "NotifyOnCrashRecovery", config.NotifyOnCrashRecovery);
            config.EnableDailySummary = ReadBool(values, "EnableDailySummary", config.EnableDailySummary);
            config.DailySummaryIntervalHours = ReadInt(values, "DailySummaryIntervalHours", config.DailySummaryIntervalHours);
            config.DailySummaryLocalTime = ReadString(values, "DailySummaryLocalTime", config.DailySummaryLocalTime);
            config.DailySummaryTimeZoneId = ReadString(values, "DailySummaryTimeZoneId", config.DailySummaryTimeZoneId);
            config.DailySummaryScore = ReadInt(values, "DailySummaryScore", config.DailySummaryScore);
            config.HealthHeartbeatSeconds = ReadInt(values, "HealthHeartbeatSeconds", config.HealthHeartbeatSeconds);
            config.EnableOpenAiLogAnalysis = ReadBool(values, "EnableOpenAiLogAnalysis", config.EnableOpenAiLogAnalysis);
            config.OpenAIAnalysisIntervalMinutes = ReadInt(values, "OpenAIAnalysisIntervalMinutes", config.OpenAIAnalysisIntervalMinutes);
            config.OpenAIAnalysisScoreThreshold = ReadInt(values, "OpenAIAnalysisScoreThreshold", config.OpenAIAnalysisScoreThreshold);
            config.OpenAIAnalysisBaselineEmailMinimumScore = ReadInt(values, "OpenAIAnalysisBaselineEmailMinimumScore", config.OpenAIAnalysisBaselineEmailMinimumScore);
            config.OpenAIAnalysisMinimumIncludedAlertScore = ReadInt(values, "OpenAIAnalysisMinimumIncludedAlertScore", config.OpenAIAnalysisMinimumIncludedAlertScore);
            config.OpenAIAnalysisBaselineMinimumIncludedAlertScore = ReadInt(values, "OpenAIAnalysisBaselineMinimumIncludedAlertScore", config.OpenAIAnalysisBaselineMinimumIncludedAlertScore);
            config.OpenAIAnalysisExcludedRuleIds = ReadStringSet(values, "OpenAIAnalysisExcludedRuleIds");
            config.OpenAIAnalysisModel = ReadString(values, "OpenAIAnalysisModel", config.OpenAIAnalysisModel);
            config.OpenAIApiKeyEnvironmentVariable = ReadString(values, "OpenAIApiKeyEnvironmentVariable", config.OpenAIApiKeyEnvironmentVariable);
            config.OpenAIAnalysisMaxLogLines = ReadInt(values, "OpenAIAnalysisMaxLogLines", config.OpenAIAnalysisMaxLogLines);
            config.OpenAIAnalysisMaxAlertLines = ReadInt(values, "OpenAIAnalysisMaxAlertLines", config.OpenAIAnalysisMaxAlertLines);
            config.OpenAIAnalysisMaxChars = ReadInt(values, "OpenAIAnalysisMaxChars", config.OpenAIAnalysisMaxChars);
            config.OpenAIAnalysisApiUrl = ReadString(values, "OpenAIAnalysisApiUrl", config.OpenAIAnalysisApiUrl);
            config.DetectEncodedCommandLines = ReadBool(values, "DetectEncodedCommandLines", config.DetectEncodedCommandLines);
            config.EncodedCommandMinimumLength = ReadInt(values, "EncodedCommandMinimumLength", config.EncodedCommandMinimumLength);
            config.ExternalAlertProvider = ReadString(values, "ExternalAlertProvider", config.ExternalAlertProvider);
            config.BrevoApiUrl = ReadString(values, "BrevoApiUrl", config.BrevoApiUrl);
            config.BrevoApiKeyEnvironmentVariable = ReadString(values, "BrevoApiKeyEnvironmentVariable", config.BrevoApiKeyEnvironmentVariable);
            config.BrevoSenderEmail = ReadString(values, "BrevoSenderEmail", "");
            config.BrevoSenderName = ReadString(values, "BrevoSenderName", config.BrevoSenderName);
            config.BrevoRecipientEmail = ReadString(values, "BrevoRecipientEmail", "");
            config.BrevoRecipientName = ReadString(values, "BrevoRecipientName", "");
            config.SmtpHost = ReadString(values, "SmtpHost", "");
            config.SmtpPort = ReadInt(values, "SmtpPort", config.SmtpPort);
            config.SmtpEnableSsl = ReadBool(values, "SmtpEnableSsl", config.SmtpEnableSsl);
            config.SmtpTimeoutSeconds = ReadInt(values, "SmtpTimeoutSeconds", config.SmtpTimeoutSeconds);
            config.SmtpUsername = ReadString(values, "SmtpUsername", "");
            config.SmtpPasswordEnvironmentVariable = ReadString(values, "SmtpPasswordEnvironmentVariable", "");
            config.SmtpSenderEmail = ReadString(values, "SmtpSenderEmail", "");
            config.SmtpSenderName = ReadString(values, "SmtpSenderName", config.SmtpSenderName);
            config.SmtpRecipientEmail = ReadString(values, "SmtpRecipientEmail", "");
            config.SmtpRecipientName = ReadString(values, "SmtpRecipientName", "");
            config.WebhookAlertUrl = ReadString(values, "WebhookAlertUrl", "");
            config.WebhookSecretEnvironmentVariable = ReadString(values, "WebhookSecretEnvironmentVariable", "");
            config.WebhookSecretHeaderName = ReadString(values, "WebhookSecretHeaderName", config.WebhookSecretHeaderName);
            config.WebhookSecretPrefix = ReadString(values, "WebhookSecretPrefix", config.WebhookSecretPrefix);
            config.WebhookTimeoutSeconds = ReadInt(values, "WebhookTimeoutSeconds", config.WebhookTimeoutSeconds);
            config.GenericHttpApiAlertUrl = ReadString(values, "GenericHttpApiAlertUrl", "");
            config.GenericHttpApiSecretEnvironmentVariable = ReadString(values, "GenericHttpApiSecretEnvironmentVariable", "");
            config.GenericHttpApiSecretHeaderName = ReadString(values, "GenericHttpApiSecretHeaderName", config.GenericHttpApiSecretHeaderName);
            config.GenericHttpApiSecretPrefix = ReadString(values, "GenericHttpApiSecretPrefix", config.GenericHttpApiSecretPrefix);
            config.GenericHttpApiTimeoutSeconds = ReadInt(values, "GenericHttpApiTimeoutSeconds", config.GenericHttpApiTimeoutSeconds);
            config.LocalJsonlAlertSinkFile = ResolvePath(config.LogDirectory, ReadString(values, "LocalJsonlAlertSinkFile", config.LocalJsonlAlertSinkFile));
            config.WindowsEventLogAlertSource = ReadString(values, "WindowsEventLogAlertSource", config.WindowsEventLogAlertSource);
            config.WindowsEventLogAlertLogName = ReadString(values, "WindowsEventLogAlertLogName", config.WindowsEventLogAlertLogName);
            config.WindowsEventLogAlertEventId = ReadInt(values, "WindowsEventLogAlertEventId", config.WindowsEventLogAlertEventId);
            config.EnableSysmonIngestion = ReadBool(values, "EnableSysmonIngestion", config.EnableSysmonIngestion);
            config.SysmonServiceName = ReadString(values, "SysmonServiceName", config.SysmonServiceName);
            config.SysmonEventLogName = ReadString(values, "SysmonEventLogName", config.SysmonEventLogName);
            config.SysmonLookbackMinutes = ReadInt(values, "SysmonLookbackMinutes", config.SysmonLookbackMinutes);
            config.SysmonMaxEventsPerPoll = ReadInt(values, "SysmonMaxEventsPerPoll", config.SysmonMaxEventsPerPoll);
            config.EnablePowerShellLogIngestion = ReadBool(values, "EnablePowerShellLogIngestion", config.EnablePowerShellLogIngestion);
            config.PowerShellEventLogName = ReadString(values, "PowerShellEventLogName", config.PowerShellEventLogName);
            config.PowerShellLookbackMinutes = ReadInt(values, "PowerShellLookbackMinutes", config.PowerShellLookbackMinutes);
            config.PowerShellMaxEventsPerPoll = ReadInt(values, "PowerShellMaxEventsPerPoll", config.PowerShellMaxEventsPerPoll);
            config.EnableWindowsEventIngestion = ReadBool(values, "EnableWindowsEventIngestion", config.EnableWindowsEventIngestion);
            config.WindowsSecurityEventLogName = ReadString(values, "WindowsSecurityEventLogName", config.WindowsSecurityEventLogName);
            config.WindowsSystemEventLogName = ReadString(values, "WindowsSystemEventLogName", config.WindowsSystemEventLogName);
            config.WindowsEventLookbackMinutes = ReadInt(values, "WindowsEventLookbackMinutes", config.WindowsEventLookbackMinutes);
            config.WindowsEventMaxEventsPerPoll = ReadInt(values, "WindowsEventMaxEventsPerPoll", config.WindowsEventMaxEventsPerPoll);
            config.EnablePersistenceInventory = ReadBool(values, "EnablePersistenceInventory", config.EnablePersistenceInventory);
            config.PersistenceInventoryIntervalMinutes = ReadInt(values, "PersistenceInventoryIntervalMinutes", config.PersistenceInventoryIntervalMinutes);
            config.EnableReputationCache = ReadBool(values, "EnableReputationCache", config.EnableReputationCache);
            config.ReputationCacheFile = ResolvePath(config.LogDirectory, ReadString(values, "ReputationCacheFile", config.ReputationCacheFile));
            config.EnableCustomRules = ReadBool(values, "EnableCustomRules", config.EnableCustomRules);
            config.CustomRulesFile = ResolvePath(Path.GetDirectoryName(config.ConfigPath), ReadString(values, "CustomRulesFile", config.CustomRulesFile));
            config.EnableIncidentGrouping = ReadBool(values, "EnableIncidentGrouping", config.EnableIncidentGrouping);
            config.IncidentStoreFile = ResolvePath(config.LogDirectory, ReadString(values, "IncidentStoreFile", config.IncidentStoreFile));
            config.IncidentWindowMinutes = ReadInt(values, "IncidentWindowMinutes", config.IncidentWindowMinutes);
            config.IncidentMinimumScore = ReadInt(values, "IncidentMinimumScore", config.IncidentMinimumScore);
            config.BaselineEnabled = ReadBool(values, "BaselineEnabled", config.BaselineEnabled);
            config.BaselineLearningMode = ReadBool(values, "BaselineLearningMode", config.BaselineLearningMode);
            config.BaselineLearningEmailMinimumScore = ReadInt(values, "BaselineLearningEmailMinimumScore", config.BaselineLearningEmailMinimumScore);
            config.BaselineWarmupHours = ReadInt(values, "BaselineWarmupHours", config.BaselineWarmupHours);
            config.BaselineFile = ResolvePath(config.LogDirectory, ReadString(values, "BaselineFile", config.BaselineFile));
            config.ResponseMode = ReadString(values, "ResponseMode", config.ResponseMode);
            config.ResponseMinimumScore = ReadInt(values, "ResponseMinimumScore", config.ResponseMinimumScore);
            config.MaxLogFileBytes = ReadLong(values, "MaxLogFileBytes", config.MaxLogFileBytes);
            config.AllowedListeningPorts = ReadPortSet(values, "AllowedListeningPorts");
            config.AllowedOutboundPorts = ReadPortSet(values, "AllowedOutboundPorts");
            config.HighRiskRemotePorts = ReadPortSet(values, "HighRiskRemotePorts");
            config.LateralMovementPorts = ReadPortSet(values, "LateralMovementPorts");
            config.TrustedProcesses = ReadStringSet(values, "TrustedProcesses");
            config.LolbinProcesses = ReadStringSet(values, "LolbinProcesses");
            config.KnownRmmProcesses = ReadStringSet(values, "KnownRmmProcesses");
            config.SuspiciousParentProcesses = ReadStringSet(values, "SuspiciousParentProcesses");
            config.SuspiciousCommandLineTerms = ReadStringSet(values, "SuspiciousCommandLineTerms");
            config.BlockedDomains = ReadStringSet(values, "BlockedDomains");
            config.BlockedHashes = ReadStringSet(values, "BlockedHashes");
            config.DynamicDnsSuffixes = ReadStringSet(values, "DynamicDnsSuffixes");
            config.UserWritablePathIndicators = ReadStringSet(values, "UserWritablePathIndicators");
            config.TrustedPersistencePathIndicators = ReadStringSet(values, "TrustedPersistencePathIndicators");
            config.TrustedPersistenceNamePrefixes = ReadStringSet(values, "TrustedPersistenceNamePrefixes");
            config.EnableAgentProfile = ReadBool(values, "EnableAgentProfile", config.EnableAgentProfile);
            config.AgentProcessNames = ReadStringSet(values, "AgentProcessNames");
            config.AgentChildProcessNames = ReadStringSet(values, "AgentChildProcessNames");
            config.AgentWorkspaceRoots = NormalizePathIndicators(ReadStringSet(values, "AgentWorkspaceRoots"));
            config.AgentPublishRoots = NormalizePathIndicators(ReadStringSet(values, "AgentPublishRoots"));
            config.AgentPackageManagerProcesses = ReadStringSet(values, "AgentPackageManagerProcesses");
            config.AgentApprovedAdminTaskNames = ReadStringSet(values, "AgentApprovedAdminTaskNames");
            config.AgentSecretIndicatorTerms = ReadStringSet(values, "AgentSecretIndicatorTerms");
            config.EnforceAuthorizedDnsResolvers = ReadBool(values, "EnforceAuthorizedDnsResolvers", false);
            config.AllowedDnsResolvers = ReadIpSet(values, "AllowedDnsResolvers");
            config.ConnectionBurstThreshold = ReadInt(values, "ConnectionBurstThreshold", config.ConnectionBurstThreshold);
            config.BeaconMinimumSamples = ReadInt(values, "BeaconMinimumSamples", config.BeaconMinimumSamples);
            config.BeaconMaxAverageIntervalSeconds = ReadInt(values, "BeaconMaxAverageIntervalSeconds", config.BeaconMaxAverageIntervalSeconds);
            config.BeaconMaxJitterRatio = ReadDouble(values, "BeaconMaxJitterRatio", config.BeaconMaxJitterRatio);
            ReadCidrList(values, "AllowedRemoteCidrs", config.allowedRemoteCidrs);
            ReadCidrList(values, "BlockedRemoteCidrs", config.blockedRemoteCidrs);
            ReadCidrList(values, "DohProviderCidrs", config.dohProviderCidrs);

            return config;
        }

        public bool IsAllowedRemote(IPAddress address)
        {
            return Contains(allowedRemoteCidrs, address);
        }

        public bool IsBlockedRemote(IPAddress address)
        {
            return Contains(blockedRemoteCidrs, address);
        }

        public bool IsAllowedDnsResolver(IPAddress address)
        {
            return AllowedDnsResolvers.Contains(address);
        }

        public bool IsDohProvider(IPAddress address)
        {
            return Contains(dohProviderCidrs, address);
        }

        public bool IsBlockedDomain(string domain)
        {
            return DomainMatchesSet(domain, BlockedDomains);
        }

        public bool IsDynamicDnsDomain(string domain)
        {
            return DomainMatchesSet(domain, DynamicDnsSuffixes);
        }

        public bool IsBlockedHash(string hash)
        {
            return !String.IsNullOrWhiteSpace(hash) && BlockedHashes.Contains(hash);
        }

        public IEnumerable<string> GetExternalAlertProviders()
        {
            if (String.IsNullOrWhiteSpace(ExternalAlertProvider))
            {
                yield return "Disabled";
                yield break;
            }

            char[] separators = new[] { ',', ';', '+' };
            foreach (string raw in ExternalAlertProvider.Split(separators, StringSplitOptions.RemoveEmptyEntries))
            {
                string provider = raw.Trim();
                if (provider.Length > 0) yield return provider;
            }
        }

        private static bool Contains(List<CidrRange> ranges, IPAddress address)
        {
            foreach (CidrRange range in ranges)
            {
                if (range.Contains(address)) return true;
            }

            return false;
        }

        private static bool DomainMatchesSet(string domain, HashSet<string> patterns)
        {
            if (String.IsNullOrWhiteSpace(domain)) return false;
            string normalized = domain.Trim().TrimEnd('.').ToLowerInvariant();
            foreach (string raw in patterns)
            {
                string pattern = raw.Trim().TrimEnd('.').ToLowerInvariant();
                if (pattern.Length == 0) continue;
                if (normalized.Equals(pattern, StringComparison.OrdinalIgnoreCase)) return true;
                if (normalized.EndsWith("." + pattern, StringComparison.OrdinalIgnoreCase)) return true;
            }

            return false;
        }

        private static string ResolveConfigPath(string baseDirectory)
        {
            string configPath = Path.Combine(baseDirectory, "config\\ArcaneEDR.config");
            if (File.Exists(configPath)) return configPath;

            DirectoryInfo baseInfo = new DirectoryInfo(baseDirectory);
            if (baseInfo.Parent != null)
            {
                configPath = Path.Combine(baseInfo.Parent.FullName, "config\\ArcaneEDR.config");
                if (File.Exists(configPath)) return configPath;
            }

            configPath = Path.Combine(Directory.GetCurrentDirectory(), "config\\ArcaneEDR.config");
            if (File.Exists(configPath)) return configPath;

            configPath = Path.Combine(baseDirectory, "config\\ArcaneEDR.example.config");
            if (File.Exists(configPath)) return configPath;

            if (baseInfo.Parent != null)
            {
                configPath = Path.Combine(baseInfo.Parent.FullName, "config\\ArcaneEDR.example.config");
                if (File.Exists(configPath)) return configPath;
            }

            return Path.Combine(Directory.GetCurrentDirectory(), "config\\ArcaneEDR.example.config");
        }

        private static string ResolvePath(string baseDirectory, string path)
        {
            if (Path.IsPathRooted(path)) return Path.GetFullPath(path);
            return Path.GetFullPath(Path.Combine(baseDirectory, path));
        }

        private static Dictionary<string, string> ReadConfigFile(string configPath)
        {
            Dictionary<string, string> values = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            foreach (string rawLine in File.ReadAllLines(configPath))
            {
                string line = rawLine.Trim();
                if (line.Length == 0 || line.StartsWith("#", StringComparison.Ordinal)) continue;
                int equals = line.IndexOf('=');
                if (equals <= 0) continue;
                values[line.Substring(0, equals).Trim()] = line.Substring(equals + 1).Trim();
            }

            return values;
        }

        private static string ReadString(Dictionary<string, string> values, string key, string fallback)
        {
            string value;
            return values.TryGetValue(key, out value) ? value : fallback;
        }

        private static int ReadInt(Dictionary<string, string> values, string key, int fallback)
        {
            string value;
            int parsed;
            return values.TryGetValue(key, out value) && Int32.TryParse(value, out parsed) ? parsed : fallback;
        }

        private static long ReadLong(Dictionary<string, string> values, string key, long fallback)
        {
            string value;
            long parsed;
            return values.TryGetValue(key, out value) && Int64.TryParse(value, out parsed) ? parsed : fallback;
        }

        private static double ReadDouble(Dictionary<string, string> values, string key, double fallback)
        {
            string value;
            double parsed;
            return values.TryGetValue(key, out value) && Double.TryParse(value, out parsed) ? parsed : fallback;
        }

        private static bool ReadBool(Dictionary<string, string> values, string key, bool fallback)
        {
            string value;
            bool parsed;
            return values.TryGetValue(key, out value) && Boolean.TryParse(value, out parsed) ? parsed : fallback;
        }

        private static PortRuleSet ReadPortSet(Dictionary<string, string> values, string key)
        {
            PortRuleSet result = new PortRuleSet();
            string value;
            if (!values.TryGetValue(key, out value)) return result;
            foreach (string part in value.Split(','))
            {
                result.Add(part.Trim());
            }

            return result;
        }

        private static HashSet<string> ReadStringSet(Dictionary<string, string> values, string key)
        {
            HashSet<string> result = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            string value;
            if (!values.TryGetValue(key, out value)) return result;
            foreach (string part in value.Split(','))
            {
                string trimmed = part.Trim();
                if (trimmed.Length > 0) result.Add(trimmed);
            }

            return result;
        }

        private static Dictionary<string, int> ReadStringIntMap(Dictionary<string, string> values, string key)
        {
            Dictionary<string, int> result = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
            string value;
            if (!values.TryGetValue(key, out value)) return result;

            foreach (string part in value.Split(','))
            {
                string item = part.Trim();
                if (item.Length == 0) continue;

                int separator = item.IndexOf('=');
                if (separator <= 0) separator = item.IndexOf(':');
                if (separator <= 0) continue;

                string name = item.Substring(0, separator).Trim();
                string scoreText = item.Substring(separator + 1).Trim();
                int score;
                if (name.Length > 0 && Int32.TryParse(scoreText, out score))
                {
                    result[name] = score;
                }
            }

            return result;
        }

        private static HashSet<string> NormalizePathIndicators(HashSet<string> values)
        {
            HashSet<string> result = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (string value in values)
            {
                string trimmed = value.Trim();
                if (trimmed.Length == 0) continue;

                try
                {
                    if (Path.IsPathRooted(trimmed))
                    {
                        trimmed = Path.GetFullPath(trimmed);
                    }
                }
                catch
                {
                }

                result.Add(trimmed.TrimEnd('\\') + "\\");
            }

            return result;
        }

        private static HashSet<IPAddress> ReadIpSet(Dictionary<string, string> values, string key)
        {
            HashSet<IPAddress> result = new HashSet<IPAddress>();
            string value;
            if (!values.TryGetValue(key, out value)) return result;
            foreach (string part in value.Split(','))
            {
                IPAddress address;
                if (IPAddress.TryParse(part.Trim(), out address)) result.Add(address);
            }

            return result;
        }

        private static void ReadCidrList(Dictionary<string, string> values, string key, List<CidrRange> target)
        {
            string value;
            if (!values.TryGetValue(key, out value)) return;
            foreach (string part in value.Split(','))
            {
                CidrRange range;
                if (CidrRange.TryParse(part.Trim(), out range)) target.Add(range);
            }
        }
    }
}
