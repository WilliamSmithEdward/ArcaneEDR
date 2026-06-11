using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Web.Script.Serialization;

namespace ArcaneEDR
{
    internal sealed class MonitorConfig
    {
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
        public bool EnableDetectionPolicy = true;
        public string PolicyFile = "arcane-policy.example.json";
        public string DetectionPolicyFile = "arcane-policy.example.json";
        public Dictionary<string, int> ExternalAlertProviderMinimumScores = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        public Dictionary<string, int> ExternalAlertProviderMaxPerHour = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        public int ExternalAlertMaxPerDispatch = 3;
        public int ExternalAlertMaxPerHour = 24;
        public bool EnableExternalAlertGrouping = true;
        public int ExternalAlertGroupingMinimumCount = 2;
        public int ExternalAlertGroupingMaximumScore = 89;
        public int ExternalAlertGroupingMaxItems = 8;
        public HashSet<string> ExternalAlertGroupingCategories = DefaultExternalAlertGroupingCategories();
        public HashSet<string> ExternalAlertSuppressionTermGroups = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        public bool EnableLowValueRepeatDampening = true;
        public int LowValueRepeatDampeningMaximumScore = 60;
        public int LowValueRepeatDampeningWindowMinutes = 60;
        public int LowValueRepeatDampeningMaxExternalAlertsPerWindow = 1;
        public HashSet<string> LowValueRepeatDampeningCategories = DefaultLowValueRepeatDampeningCategories();
        public bool EnableMaintenanceContext = true;
        public HashSet<string> MaintenanceContextTermGroups = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        public int MaintenanceContextExternalAlertMinimumScore = 95;
        public bool EnableMaintenanceSessionMarkers = true;
        public string MaintenanceSessionMarkerFile = "ArcaneMaintenanceSessions.jsonl";
        public int MaintenanceSessionDefaultMinutes = 60;
        public int MaintenanceSessionMaximumMinutes = 240;
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
        public bool EnableDailySummaryAIAnalysis = true;
        public HashSet<string> DailyReportDestinations = DefaultDailyReportDestinations();
        public HashSet<string> DailyReportSections = DefaultDailyReportSections();
        public int DailyReportCriticalCalloutRows = 5;
        public int DailyReportHighSignalRows = 7;
        public int DailyReportBucketRows = 6;
        public int DailyReportAgentBucketRows = 3;
        public bool EnableDailyReportArchive = true;
        public string DailyReportArchiveDirectory = "reports";
        public HashSet<string> DailyReportArchiveFormats = DefaultDailyReportArchiveFormats();
        public string DailyReportWebhookUrl;
        public string DailyReportWebhookSecretEnvironmentVariable;
        public string DailyReportWebhookSecretHeaderName = "Authorization";
        public string DailyReportWebhookSecretPrefix = "Bearer ";
        public int DailyReportWebhookTimeoutSeconds = 15;
        public int HealthHeartbeatSeconds = 60;
        public bool EnableAIAnalysis;
        public int AIAnalysisIntervalMinutes = 60;
        public int AIAnalysisScoreThreshold = 95;
        public int AIAnalysisBaselineEmailMinimumScore = 95;
        public int AIAnalysisMinimumIncludedAlertScore = 60;
        public int AIAnalysisBaselineMinimumIncludedAlertScore = 90;
        public HashSet<string> AIAnalysisExcludedRuleIds = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        public List<string> AIAnalysisProviders = new List<string>();
        public Dictionary<string, string> AIAnalysisProviderTypes = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        public Dictionary<string, string> AIAnalysisProviderModels = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        public Dictionary<string, string> AIAnalysisProviderApiUrls = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        public Dictionary<string, string> AIAnalysisProviderApiKeyEnvironmentVariables = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        public Dictionary<string, string> AIAnalysisProviderAuthHeaderNames = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        public Dictionary<string, string> AIAnalysisProviderAuthHeaderPrefixes = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        public Dictionary<string, string> AIAnalysisProviderVersionHeaderNames = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        public Dictionary<string, string> AIAnalysisProviderVersionHeaderValues = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        public string AIAnalysisModel = "";
        public string AIAnalysisApiKeyEnvironmentVariable = "";
        public string AIAnalysisApiUrl = "";
        public string AIAnalysisAuthHeaderName = "";
        public string AIAnalysisAuthHeaderPrefix = "";
        public int AIAnalysisMaxLogLines = 80;
        public int AIAnalysisMaxAlertLines = 80;
        public int AIAnalysisMaxChars = 12000;
        public int AIAnalysisTimeoutSeconds = 30;
        public bool DetectEncodedCommandLines = true;
        public int EncodedCommandMinimumLength = 80;
        public string ExternalAlertProvider = "Disabled";
        public string BrevoApiUrl = "https://api.brevo.com/v3/smtp/email";
        public string BrevoApiKeyEnvironmentVariable = "BREVO_API_KEY";
        public string BrevoSenderEmail;
        public string BrevoSenderName = "Arcane EDR";
        public string BrevoRecipientEmail;
        public string BrevoRecipientName;
        public int BrevoTimeoutSeconds = 15;
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
        public bool EnableNetstatCollector = true;
        public bool EnableSysmonIngestion = true;
        public string SysmonServiceName = "Sysmon";
        public string SysmonEventLogName = "Microsoft-Windows-Sysmon/Operational";
        public int SysmonLookbackMinutes = 10;
        public int SysmonMaxEventsPerPoll = 200;
        public bool PersistEventLogWatermarks = true;
        public string EventLogWatermarkFile = "ArcaneEventLogWatermarks.tsv";
        public bool EnablePowerShellLogIngestion = true;
        public string PowerShellEventLogName = "Microsoft-Windows-PowerShell/Operational";
        public int PowerShellLookbackMinutes = 10;
        public int PowerShellMaxEventsPerPoll = 200;
        public bool EnableWindowsEventIngestion = true;
        public string WindowsSecurityEventLogName = "Security";
        public string WindowsSystemEventLogName = "System";
        public int WindowsEventLookbackMinutes = 10;
        public int WindowsEventMaxEventsPerPoll = 200;
        public int AuthSpecialPrivilegeRepeatDampeningMinutes = 60;
        public int AuthSpecialPrivilegeRemoteCorrelationMinutes = 15;
        public bool EnablePersistenceInventory = true;
        public int PersistenceInventoryIntervalMinutes = 60;
        public bool EnableHighSignalFileDetection = true;
        public HashSet<string> HighRiskFilePathIndicators = DefaultHighRiskFilePathIndicators();
        public HashSet<string> HighRiskFileExtensions = DefaultHighRiskFileExtensions();
        public HashSet<string> SensitiveFileNameIndicators = DefaultSensitiveFileNameIndicators();
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
        public bool EnableFirewallBlockResponse;
        public bool EnableProcessTerminationResponse;
        public bool EnableResponsePolicy = true;
        public HashSet<string> ResponseAllowedRuleIds = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        public HashSet<string> ResponseAllowedCategories = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        public HashSet<string> ResponseBlockedRuleIds = DefaultResponseBlockedRuleIds();
        public HashSet<string> ResponseBlockedCategories = DefaultResponseBlockedCategories();
        public HashSet<string> ResponseProtectedProcessNames = DefaultResponseProtectedProcessNames();
        public bool EnableResponseLedger = true;
        public string ResponseLedgerFile = "ArcaneResponseLedger.jsonl";
        public bool EnableResponseFollowUpDetections = true;
        public int ResponseProcessRespawnWindowMinutes = 10;
        public int ResponseProcessRespawnMinimumScore = 94;
        public int ResponseFollowUpExternalAlertMinimumScore = 95;
        public long MaxLogFileBytes = 10485760;
        public PortRuleSet AllowedListeningPorts = new PortRuleSet();
        public PortRuleSet AllowedOutboundPorts = new PortRuleSet();
        public Dictionary<string, PortRuleSet> ProcessAllowedOutboundPorts = new Dictionary<string, PortRuleSet>(StringComparer.OrdinalIgnoreCase);
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
        public HashSet<string> TrustedPersistenceSignerSubjects = DefaultTrustedPersistenceSignerSubjects();
        public bool EnableAgentProfile = true;
        public HashSet<string> AgentProcessNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        public HashSet<string> AgentChildProcessNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        public HashSet<string> AgentWorkspaceRoots = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        public HashSet<string> AgentPublishRoots = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        public HashSet<string> AgentPackageManagerProcesses = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        public HashSet<string> AgentApprovedAdminTaskNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        public HashSet<string> AgentSecretIndicatorTerms = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        public bool EnableAgentAdminCommandGuardrails = true;
        public int AgentAdminCommandMinimumScore = 84;
        public HashSet<string> AgentAdminCommandTerms = DefaultAgentAdminCommandTerms();
        public bool EnableAgentSecretReferenceGuardrails = true;
        public int AgentSecretReferenceMinimumScore = 78;
        public HashSet<string> AgentSecretReferenceTerms = DefaultAgentSecretReferenceTerms();
        public bool EnableAgentSupplyChainGuardrails = true;
        public int AgentSupplyChainMinimumScore = 74;
        public HashSet<string> AgentSupplyChainTerms = DefaultAgentSupplyChainTerms();
        public bool EnableAgentActivityLedger = true;
        public string AgentActivityLedgerFile = "ArcaneAgentActivity.jsonl";
        public int AgentActivityLedgerMinimumScore = 60;
        public HashSet<IPAddress> AllowedDnsResolvers = new HashSet<IPAddress>();
        public HashSet<string> AllowedRemoteCountries = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        public bool EnforceAuthorizedDnsResolvers;
        public bool EnableRemoteEndpointEnrichment = true;
        public bool EnableRemoteEndpointCountryBlockEnrichment;
        public string RemoteEndpointCountryBlocksDirectory = "country-ip-blocks";
        public bool EnableRemoteEndpointIpApiGeolocation;
        public string RemoteEndpointIpApiUrlTemplate = "http://ip-api.com/json/{ip}?fields=status,message,countryCode,org,isp,as,asname,query";
        public bool EnableRemoteEndpointIpWhoisGeolocation;
        public string RemoteEndpointIpWhoisUrlTemplate = "https://ipwho.is/{ip}?fields=success,message,country_code,org,isp,asn,ip";
        public int RemoteEndpointGeoProviderMaxLookupsPerPoll = 3;
        public bool EnableRemoteEndpointReverseDns;
        public bool EnableRemoteEndpointRdapEnrichment = true;
        public string RemoteEndpointRdapUrlTemplate = "https://rdap.org/ip/{ip}";
        public int RemoteEndpointEnrichmentTimeoutSeconds = 3;
        public int RemoteEndpointEnrichmentCacheMinutes = 1440;
        public int RemoteEndpointRdapMaxLookupsPerPoll = 3;
        public bool EnableRemoteEndpointPolicy = true;
        public string RemoteEndpointPolicyFile = "arcane-policy.example.json";
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
            return Load(baseDirectory, "");
        }

        public static MonitorConfig Load(string baseDirectory, string explicitConfigPath)
        {
            string configPath = String.IsNullOrWhiteSpace(explicitConfigPath)
                ? ResolveConfigPath(baseDirectory)
                : ResolvePath(Directory.GetCurrentDirectory(), explicitConfigPath);
            Dictionary<string, string> values = ReadConfigFile(configPath);

            MonitorConfig config = new MonitorConfig();
            config.ConfigPath = configPath;
            string configDirectory = Path.GetDirectoryName(config.ConfigPath);
            config.PolicyFile = ResolvePath(configDirectory, ReadString(values, "PolicyFile", config.PolicyFile));
            config.DetectionPolicyFile = config.PolicyFile;
            config.RemoteEndpointPolicyFile = config.PolicyFile;
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
            config.EnableDetectionPolicy = ReadBool(values, "EnableDetectionPolicy", config.EnableDetectionPolicy);
            config.ExternalAlertProviderMinimumScores = ReadStringIntMap(values, "ExternalAlertProviderMinimumScores");
            config.ExternalAlertProviderMaxPerHour = ReadStringIntMap(values, "ExternalAlertProviderMaxPerHour");
            config.ExternalAlertMaxPerDispatch = ReadInt(values, "ExternalAlertMaxPerDispatch", config.ExternalAlertMaxPerDispatch);
            config.ExternalAlertMaxPerHour = ReadInt(values, "ExternalAlertMaxPerHour", config.ExternalAlertMaxPerHour);
            config.EnableExternalAlertGrouping = ReadBool(values, "EnableExternalAlertGrouping", config.EnableExternalAlertGrouping);
            config.ExternalAlertGroupingMinimumCount = ReadInt(values, "ExternalAlertGroupingMinimumCount", config.ExternalAlertGroupingMinimumCount);
            config.ExternalAlertGroupingMaximumScore = ReadInt(values, "ExternalAlertGroupingMaximumScore", config.ExternalAlertGroupingMaximumScore);
            config.ExternalAlertGroupingMaxItems = ReadInt(values, "ExternalAlertGroupingMaxItems", config.ExternalAlertGroupingMaxItems);
            config.ExternalAlertGroupingCategories = values.ContainsKey("ExternalAlertGroupingCategories")
                ? ReadStringSet(values, "ExternalAlertGroupingCategories")
                : DefaultExternalAlertGroupingCategories();
            config.ExternalAlertSuppressionTermGroups = ReadStringSet(values, "ExternalAlertSuppressionTermGroups");
            config.EnableLowValueRepeatDampening = ReadBool(values, "EnableLowValueRepeatDampening", config.EnableLowValueRepeatDampening);
            config.LowValueRepeatDampeningMaximumScore = ReadInt(values, "LowValueRepeatDampeningMaximumScore", config.LowValueRepeatDampeningMaximumScore);
            config.LowValueRepeatDampeningWindowMinutes = ReadInt(values, "LowValueRepeatDampeningWindowMinutes", config.LowValueRepeatDampeningWindowMinutes);
            config.LowValueRepeatDampeningMaxExternalAlertsPerWindow = ReadInt(values, "LowValueRepeatDampeningMaxExternalAlertsPerWindow", config.LowValueRepeatDampeningMaxExternalAlertsPerWindow);
            config.LowValueRepeatDampeningCategories = values.ContainsKey("LowValueRepeatDampeningCategories")
                ? ReadStringSet(values, "LowValueRepeatDampeningCategories")
                : DefaultLowValueRepeatDampeningCategories();
            config.EnableMaintenanceContext = ReadBool(values, "EnableMaintenanceContext", config.EnableMaintenanceContext);
            config.MaintenanceContextTermGroups = ReadStringSet(values, "MaintenanceContextTermGroups");
            config.MaintenanceContextExternalAlertMinimumScore = ReadInt(values, "MaintenanceContextExternalAlertMinimumScore", config.MaintenanceContextExternalAlertMinimumScore);
            config.RequireExternalAlerting = ReadBool(values, "RequireExternalAlerting", ReadBool(values, "RequireEmailConfig", false));
            config.LogDirectory = ResolvePath(baseDirectory, ReadString(values, "LogDirectory", "logs"));
            config.EnableMaintenanceSessionMarkers = ReadBool(values, "EnableMaintenanceSessionMarkers", config.EnableMaintenanceSessionMarkers);
            config.MaintenanceSessionMarkerFile = ResolvePath(config.LogDirectory, ReadString(values, "MaintenanceSessionMarkerFile", config.MaintenanceSessionMarkerFile));
            config.MaintenanceSessionDefaultMinutes = ReadInt(values, "MaintenanceSessionDefaultMinutes", config.MaintenanceSessionDefaultMinutes);
            config.MaintenanceSessionMaximumMinutes = ReadInt(values, "MaintenanceSessionMaximumMinutes", config.MaintenanceSessionMaximumMinutes);
            config.PersistEventLogWatermarks = ReadBool(values, "PersistEventLogWatermarks", config.PersistEventLogWatermarks);
            config.EventLogWatermarkFile = ResolvePath(config.LogDirectory, ReadString(values, "EventLogWatermarkFile", config.EventLogWatermarkFile));
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
            config.EnableDailySummaryAIAnalysis = ReadBool(values, "EnableDailySummaryAIAnalysis", config.EnableDailySummaryAIAnalysis);
            config.DailyReportDestinations = values.ContainsKey("DailyReportDestinations")
                ? ReadStringSet(values, "DailyReportDestinations")
                : DefaultDailyReportDestinations();
            if (config.DailyReportDestinations.Count == 0) config.DailyReportDestinations = DefaultDailyReportDestinations();
            config.DailyReportSections = values.ContainsKey("DailyReportSections")
                ? ReadStringSet(values, "DailyReportSections")
                : DefaultDailyReportSections();
            if (config.DailyReportSections.Count == 0) config.DailyReportSections = DefaultDailyReportSections();
            config.DailyReportCriticalCalloutRows = ReadInt(values, "DailyReportCriticalCalloutRows", config.DailyReportCriticalCalloutRows);
            config.DailyReportHighSignalRows = ReadInt(values, "DailyReportHighSignalRows", config.DailyReportHighSignalRows);
            config.DailyReportBucketRows = ReadInt(values, "DailyReportBucketRows", config.DailyReportBucketRows);
            config.DailyReportAgentBucketRows = ReadInt(values, "DailyReportAgentBucketRows", config.DailyReportAgentBucketRows);
            config.EnableDailyReportArchive = ReadBool(values, "EnableDailyReportArchive", config.EnableDailyReportArchive);
            config.DailyReportArchiveDirectory = ResolvePath(config.LogDirectory, ReadString(values, "DailyReportArchiveDirectory", config.DailyReportArchiveDirectory));
            config.DailyReportArchiveFormats = values.ContainsKey("DailyReportArchiveFormats")
                ? ReadStringSet(values, "DailyReportArchiveFormats")
                : DefaultDailyReportArchiveFormats();
            if (config.DailyReportArchiveFormats.Count == 0) config.DailyReportArchiveFormats = DefaultDailyReportArchiveFormats();
            config.DailyReportWebhookUrl = ReadString(values, "DailyReportWebhookUrl", "");
            config.DailyReportWebhookSecretEnvironmentVariable = ReadString(values, "DailyReportWebhookSecretEnvironmentVariable", "");
            config.DailyReportWebhookSecretHeaderName = ReadString(values, "DailyReportWebhookSecretHeaderName", config.DailyReportWebhookSecretHeaderName);
            config.DailyReportWebhookSecretPrefix = ReadString(values, "DailyReportWebhookSecretPrefix", config.DailyReportWebhookSecretPrefix);
            config.DailyReportWebhookTimeoutSeconds = ReadInt(values, "DailyReportWebhookTimeoutSeconds", config.DailyReportWebhookTimeoutSeconds);
            config.HealthHeartbeatSeconds = ReadInt(values, "HealthHeartbeatSeconds", config.HealthHeartbeatSeconds);
            config.EnableAIAnalysis = ReadBool(values, "EnableAIAnalysis", config.EnableAIAnalysis);
            config.AIAnalysisIntervalMinutes = ReadInt(values, "AIAnalysisIntervalMinutes", config.AIAnalysisIntervalMinutes);
            config.AIAnalysisScoreThreshold = ReadInt(values, "AIAnalysisScoreThreshold", config.AIAnalysisScoreThreshold);
            config.AIAnalysisBaselineEmailMinimumScore = ReadInt(values, "AIAnalysisBaselineEmailMinimumScore", config.AIAnalysisBaselineEmailMinimumScore);
            config.AIAnalysisMinimumIncludedAlertScore = ReadInt(values, "AIAnalysisMinimumIncludedAlertScore", config.AIAnalysisMinimumIncludedAlertScore);
            config.AIAnalysisBaselineMinimumIncludedAlertScore = ReadInt(values, "AIAnalysisBaselineMinimumIncludedAlertScore", config.AIAnalysisBaselineMinimumIncludedAlertScore);
            config.AIAnalysisExcludedRuleIds = ReadStringSet(values, "AIAnalysisExcludedRuleIds");
            config.AIAnalysisProviders = ReadStringList(values, "AIAnalysisProviders");
            config.AIAnalysisProviderTypes = ReadStringMap(values, "AIAnalysisProviderTypes");
            config.AIAnalysisProviderModels = ReadStringMap(values, "AIAnalysisProviderModels");
            config.AIAnalysisProviderApiUrls = ReadStringMap(values, "AIAnalysisProviderApiUrls");
            config.AIAnalysisProviderApiKeyEnvironmentVariables = ReadStringMap(values, "AIAnalysisProviderApiKeyEnvironmentVariables");
            config.AIAnalysisProviderAuthHeaderNames = ReadStringMap(values, "AIAnalysisProviderAuthHeaderNames");
            config.AIAnalysisProviderAuthHeaderPrefixes = ReadStringMap(values, "AIAnalysisProviderAuthHeaderPrefixes");
            config.AIAnalysisProviderVersionHeaderNames = ReadStringMap(values, "AIAnalysisProviderVersionHeaderNames");
            config.AIAnalysisProviderVersionHeaderValues = ReadStringMap(values, "AIAnalysisProviderVersionHeaderValues");
            config.AIAnalysisMaxLogLines = ReadInt(values, "AIAnalysisMaxLogLines", config.AIAnalysisMaxLogLines);
            config.AIAnalysisMaxAlertLines = ReadInt(values, "AIAnalysisMaxAlertLines", config.AIAnalysisMaxAlertLines);
            config.AIAnalysisMaxChars = ReadInt(values, "AIAnalysisMaxChars", config.AIAnalysisMaxChars);
            config.AIAnalysisTimeoutSeconds = ReadInt(values, "AIAnalysisTimeoutSeconds", config.AIAnalysisTimeoutSeconds);
            config.AIAnalysisModel = ReadString(values, "AIAnalysisModel", config.AIAnalysisModel);
            config.AIAnalysisApiKeyEnvironmentVariable = ReadString(values, "AIAnalysisApiKeyEnvironmentVariable", config.AIAnalysisApiKeyEnvironmentVariable);
            config.AIAnalysisApiUrl = ReadString(values, "AIAnalysisApiUrl", config.AIAnalysisApiUrl);
            config.AIAnalysisAuthHeaderName = ReadString(values, "AIAnalysisAuthHeaderName", config.AIAnalysisAuthHeaderName);
            config.AIAnalysisAuthHeaderPrefix = ReadString(values, "AIAnalysisAuthHeaderPrefix", config.AIAnalysisAuthHeaderPrefix);
            config.DetectEncodedCommandLines = ReadBool(values, "DetectEncodedCommandLines", config.DetectEncodedCommandLines);
            config.EncodedCommandMinimumLength = ReadInt(values, "EncodedCommandMinimumLength", config.EncodedCommandMinimumLength);
            config.ExternalAlertProvider = ReadString(values, "ExternalAlertProvider", config.ExternalAlertProvider);
            config.BrevoApiUrl = ReadString(values, "BrevoApiUrl", config.BrevoApiUrl);
            config.BrevoApiKeyEnvironmentVariable = ReadString(values, "BrevoApiKeyEnvironmentVariable", config.BrevoApiKeyEnvironmentVariable);
            config.BrevoSenderEmail = ReadString(values, "BrevoSenderEmail", "");
            config.BrevoSenderName = ReadString(values, "BrevoSenderName", config.BrevoSenderName);
            config.BrevoRecipientEmail = ReadString(values, "BrevoRecipientEmail", "");
            config.BrevoRecipientName = ReadString(values, "BrevoRecipientName", "");
            config.BrevoTimeoutSeconds = ReadInt(values, "BrevoTimeoutSeconds", config.BrevoTimeoutSeconds);
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
            config.EnableNetstatCollector = ReadBool(values, "EnableNetstatCollector", config.EnableNetstatCollector);
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
            config.AuthSpecialPrivilegeRepeatDampeningMinutes = ReadInt(values, "AuthSpecialPrivilegeRepeatDampeningMinutes", config.AuthSpecialPrivilegeRepeatDampeningMinutes);
            config.AuthSpecialPrivilegeRemoteCorrelationMinutes = ReadInt(values, "AuthSpecialPrivilegeRemoteCorrelationMinutes", config.AuthSpecialPrivilegeRemoteCorrelationMinutes);
            config.EnablePersistenceInventory = ReadBool(values, "EnablePersistenceInventory", config.EnablePersistenceInventory);
            config.PersistenceInventoryIntervalMinutes = ReadInt(values, "PersistenceInventoryIntervalMinutes", config.PersistenceInventoryIntervalMinutes);
            config.EnableHighSignalFileDetection = ReadBool(values, "EnableHighSignalFileDetection", config.EnableHighSignalFileDetection);
            config.HighRiskFilePathIndicators = values.ContainsKey("HighRiskFilePathIndicators")
                ? ReadStringSet(values, "HighRiskFilePathIndicators")
                : DefaultHighRiskFilePathIndicators();
            config.HighRiskFileExtensions = values.ContainsKey("HighRiskFileExtensions")
                ? NormalizeExtensions(ReadStringSet(values, "HighRiskFileExtensions"))
                : DefaultHighRiskFileExtensions();
            config.SensitiveFileNameIndicators = values.ContainsKey("SensitiveFileNameIndicators")
                ? ReadStringSet(values, "SensitiveFileNameIndicators")
                : DefaultSensitiveFileNameIndicators();
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
            config.EnableFirewallBlockResponse = ReadBool(values, "EnableFirewallBlockResponse", config.EnableFirewallBlockResponse);
            config.EnableProcessTerminationResponse = ReadBool(values, "EnableProcessTerminationResponse", config.EnableProcessTerminationResponse);
            config.EnableResponsePolicy = ReadBool(values, "EnableResponsePolicy", config.EnableResponsePolicy);
            config.EnableResponseLedger = ReadBool(values, "EnableResponseLedger", config.EnableResponseLedger);
            config.ResponseLedgerFile = ResolvePath(config.LogDirectory, ReadString(values, "ResponseLedgerFile", config.ResponseLedgerFile));
            config.EnableResponseFollowUpDetections = ReadBool(values, "EnableResponseFollowUpDetections", config.EnableResponseFollowUpDetections);
            config.ResponseProcessRespawnWindowMinutes = ReadInt(values, "ResponseProcessRespawnWindowMinutes", config.ResponseProcessRespawnWindowMinutes);
            config.ResponseProcessRespawnMinimumScore = ReadInt(values, "ResponseProcessRespawnMinimumScore", config.ResponseProcessRespawnMinimumScore);
            config.ResponseFollowUpExternalAlertMinimumScore = ReadInt(values, "ResponseFollowUpExternalAlertMinimumScore", config.ResponseFollowUpExternalAlertMinimumScore);
            config.MaxLogFileBytes = ReadLong(values, "MaxLogFileBytes", config.MaxLogFileBytes);
            config.HighRiskRemotePorts = ReadPortSet(values, "HighRiskRemotePorts");
            config.LateralMovementPorts = ReadPortSet(values, "LateralMovementPorts");
            config.LolbinProcesses = ReadStringSet(values, "LolbinProcesses");
            config.KnownRmmProcesses = ReadStringSet(values, "KnownRmmProcesses");
            config.SuspiciousParentProcesses = ReadStringSet(values, "SuspiciousParentProcesses");
            config.SuspiciousCommandLineTerms = ReadStringSet(values, "SuspiciousCommandLineTerms");
            config.DynamicDnsSuffixes = ReadStringSet(values, "DynamicDnsSuffixes");
            config.UserWritablePathIndicators = ReadStringSet(values, "UserWritablePathIndicators");
            config.EnableAgentProfile = ReadBool(values, "EnableAgentProfile", config.EnableAgentProfile);
            config.AgentProcessNames = ReadStringSet(values, "AgentProcessNames");
            config.AgentChildProcessNames = ReadStringSet(values, "AgentChildProcessNames");
            config.AgentWorkspaceRoots = NormalizePathIndicators(ReadStringSet(values, "AgentWorkspaceRoots"));
            config.AgentPublishRoots = NormalizePathIndicators(ReadStringSet(values, "AgentPublishRoots"));
            config.AgentPackageManagerProcesses = ReadStringSet(values, "AgentPackageManagerProcesses");
            config.AgentApprovedAdminTaskNames = ReadStringSet(values, "AgentApprovedAdminTaskNames");
            config.AgentSecretIndicatorTerms = ReadStringSet(values, "AgentSecretIndicatorTerms");
            config.EnableAgentAdminCommandGuardrails = ReadBool(values, "EnableAgentAdminCommandGuardrails", config.EnableAgentAdminCommandGuardrails);
            config.AgentAdminCommandMinimumScore = ReadInt(values, "AgentAdminCommandMinimumScore", config.AgentAdminCommandMinimumScore);
            config.AgentAdminCommandTerms = values.ContainsKey("AgentAdminCommandTerms")
                ? ReadStringSet(values, "AgentAdminCommandTerms")
                : DefaultAgentAdminCommandTerms();
            config.EnableAgentSecretReferenceGuardrails = ReadBool(values, "EnableAgentSecretReferenceGuardrails", config.EnableAgentSecretReferenceGuardrails);
            config.AgentSecretReferenceMinimumScore = ReadInt(values, "AgentSecretReferenceMinimumScore", config.AgentSecretReferenceMinimumScore);
            config.AgentSecretReferenceTerms = values.ContainsKey("AgentSecretReferenceTerms")
                ? ReadStringSet(values, "AgentSecretReferenceTerms")
                : DefaultAgentSecretReferenceTerms();
            config.EnableAgentSupplyChainGuardrails = ReadBool(values, "EnableAgentSupplyChainGuardrails", config.EnableAgentSupplyChainGuardrails);
            config.AgentSupplyChainMinimumScore = ReadInt(values, "AgentSupplyChainMinimumScore", config.AgentSupplyChainMinimumScore);
            config.AgentSupplyChainTerms = values.ContainsKey("AgentSupplyChainTerms")
                ? ReadStringSet(values, "AgentSupplyChainTerms")
                : DefaultAgentSupplyChainTerms();
            config.EnableAgentActivityLedger = ReadBool(values, "EnableAgentActivityLedger", config.EnableAgentActivityLedger);
            config.AgentActivityLedgerFile = ResolvePath(config.LogDirectory, ReadString(values, "AgentActivityLedgerFile", config.AgentActivityLedgerFile));
            config.AgentActivityLedgerMinimumScore = ReadInt(values, "AgentActivityLedgerMinimumScore", config.AgentActivityLedgerMinimumScore);
            config.EnforceAuthorizedDnsResolvers = ReadBool(values, "EnforceAuthorizedDnsResolvers", false);
            config.EnableRemoteEndpointEnrichment = ReadBool(values, "EnableRemoteEndpointEnrichment", config.EnableRemoteEndpointEnrichment);
            config.EnableRemoteEndpointCountryBlockEnrichment = ReadBool(values, "EnableRemoteEndpointCountryBlockEnrichment", config.EnableRemoteEndpointCountryBlockEnrichment);
            config.RemoteEndpointCountryBlocksDirectory = ResolvePath(Path.GetDirectoryName(config.ConfigPath), ReadString(values, "RemoteEndpointCountryBlocksDirectory", config.RemoteEndpointCountryBlocksDirectory));
            config.EnableRemoteEndpointIpApiGeolocation = ReadBool(values, "EnableRemoteEndpointIpApiGeolocation", config.EnableRemoteEndpointIpApiGeolocation);
            config.RemoteEndpointIpApiUrlTemplate = ReadString(values, "RemoteEndpointIpApiUrlTemplate", config.RemoteEndpointIpApiUrlTemplate);
            config.EnableRemoteEndpointIpWhoisGeolocation = ReadBool(values, "EnableRemoteEndpointIpWhoisGeolocation", config.EnableRemoteEndpointIpWhoisGeolocation);
            config.RemoteEndpointIpWhoisUrlTemplate = ReadString(values, "RemoteEndpointIpWhoisUrlTemplate", config.RemoteEndpointIpWhoisUrlTemplate);
            config.RemoteEndpointGeoProviderMaxLookupsPerPoll = ReadInt(values, "RemoteEndpointGeoProviderMaxLookupsPerPoll", config.RemoteEndpointGeoProviderMaxLookupsPerPoll);
            config.EnableRemoteEndpointReverseDns = ReadBool(values, "EnableRemoteEndpointReverseDns", config.EnableRemoteEndpointReverseDns);
            config.EnableRemoteEndpointRdapEnrichment = ReadBool(values, "EnableRemoteEndpointRdapEnrichment", config.EnableRemoteEndpointRdapEnrichment);
            config.RemoteEndpointRdapUrlTemplate = ReadString(values, "RemoteEndpointRdapUrlTemplate", config.RemoteEndpointRdapUrlTemplate);
            config.RemoteEndpointEnrichmentTimeoutSeconds = ReadInt(values, "RemoteEndpointEnrichmentTimeoutSeconds", config.RemoteEndpointEnrichmentTimeoutSeconds);
            config.RemoteEndpointEnrichmentCacheMinutes = ReadInt(values, "RemoteEndpointEnrichmentCacheMinutes", config.RemoteEndpointEnrichmentCacheMinutes);
            config.RemoteEndpointRdapMaxLookupsPerPoll = ReadInt(values, "RemoteEndpointRdapMaxLookupsPerPoll", config.RemoteEndpointRdapMaxLookupsPerPoll);
            config.EnableRemoteEndpointPolicy = ReadBool(values, "EnableRemoteEndpointPolicy", config.EnableRemoteEndpointPolicy);
            config.ConnectionBurstThreshold = ReadInt(values, "ConnectionBurstThreshold", config.ConnectionBurstThreshold);
            config.BeaconMinimumSamples = ReadInt(values, "BeaconMinimumSamples", config.BeaconMinimumSamples);
            config.BeaconMaxAverageIntervalSeconds = ReadInt(values, "BeaconMaxAverageIntervalSeconds", config.BeaconMaxAverageIntervalSeconds);
            config.BeaconMaxJitterRatio = ReadDouble(values, "BeaconMaxJitterRatio", config.BeaconMaxJitterRatio);
            ReadCidrList(values, "DohProviderCidrs", config.dohProviderCidrs);
            LoadUnifiedPolicySettings(config);

            return config;
        }

        private static void LoadUnifiedPolicySettings(MonitorConfig config)
        {
            if (config == null || String.IsNullOrWhiteSpace(config.PolicyFile) || !File.Exists(config.PolicyFile)) return;

            IDictionary root = LoadPolicyRoot(config.PolicyFile);
            if (root == null) return;

            IDictionary allowlists = PolicySection(root, "allowlists");
            IDictionary blocklists = PolicySection(root, "blocklists");
            IDictionary response = PolicySection(root, "response_policy");

            object value;
            if (TryPolicyValue(allowlists, "allowed_listening_ports", out value)) config.AllowedListeningPorts = PolicyPortSet(value);
            if (TryPolicyValue(allowlists, "allowed_outbound_ports", out value)) config.AllowedOutboundPorts = PolicyPortSet(value);
            if (TryPolicyValue(allowlists, "process_allowed_outbound_ports", out value)) config.ProcessAllowedOutboundPorts = PolicyProcessPortMap(value);
            if (TryPolicyValue(allowlists, "trusted_processes", out value)) config.TrustedProcesses = PolicyStringSet(value);
            if (TryPolicyValue(allowlists, "allowed_dns_resolvers", out value)) config.AllowedDnsResolvers = PolicyIpSet(value);
            if (TryPolicyValue(allowlists, "allowed_remote_countries", out value)) config.AllowedRemoteCountries = PolicyCountrySet(value);
            if (TryPolicyValue(allowlists, "trusted_persistence_name_prefixes", out value)) config.TrustedPersistenceNamePrefixes = PolicyStringSet(value);
            if (TryPolicyValue(allowlists, "trusted_persistence_path_indicators", out value)) config.TrustedPersistencePathIndicators = PolicyStringSet(value);
            if (TryPolicyValue(allowlists, "trusted_persistence_signer_subjects", out value)) config.TrustedPersistenceSignerSubjects = PolicyStringSet(value);

            if (TryPolicyValue(blocklists, "blocked_domains", out value)) config.BlockedDomains = PolicyStringSet(value);
            if (TryPolicyValue(blocklists, "blocked_hashes", out value)) config.BlockedHashes = PolicyStringSet(value);

            if (TryPolicyValue(response, "allowed_rule_ids", out value)) config.ResponseAllowedRuleIds = PolicyStringSet(value);
            if (TryPolicyValue(response, "allowed_categories", out value)) config.ResponseAllowedCategories = PolicyStringSet(value);
            if (TryPolicyValue(response, "blocked_rule_ids", out value)) config.ResponseBlockedRuleIds = PolicyStringSet(value);
            if (TryPolicyValue(response, "blocked_categories", out value)) config.ResponseBlockedCategories = PolicyStringSet(value);
            if (TryPolicyValue(response, "protected_process_names", out value)) config.ResponseProtectedProcessNames = PolicyStringSet(value);
        }

        private static IDictionary LoadPolicyRoot(string path)
        {
            try
            {
                JavaScriptSerializer serializer = new JavaScriptSerializer();
                return serializer.DeserializeObject(File.ReadAllText(path)) as IDictionary;
            }
            catch
            {
                return null;
            }
        }

        private static IDictionary PolicySection(IDictionary root, string key)
        {
            object value;
            return TryPolicyValue(root, key, out value) ? value as IDictionary : null;
        }

        private static bool TryPolicyValue(IDictionary map, string key, out object value)
        {
            value = null;
            if (map == null || String.IsNullOrWhiteSpace(key)) return false;

            foreach (DictionaryEntry entry in map)
            {
                if (PolicyKeyEquals(entry.Key, key))
                {
                    value = entry.Value;
                    return true;
                }
            }

            return false;
        }

        private static bool PolicyKeyEquals(object actual, string expected)
        {
            return NormalizePolicyKey(actual).Equals(NormalizePolicyKey(expected), StringComparison.OrdinalIgnoreCase);
        }

        private static string NormalizePolicyKey(object value)
        {
            return value == null ? "" : value.ToString().Trim().Replace("-", "_").ToLowerInvariant();
        }

        private static HashSet<string> PolicyStringSet(object value)
        {
            HashSet<string> result = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            AddPolicyStringValues(result, value);
            return result;
        }

        private static void AddPolicyStringValues(HashSet<string> result, object value)
        {
            if (result == null || value == null) return;

            IList list = value as IList;
            if (list != null)
            {
                foreach (object item in list)
                {
                    AddPolicyStringValues(result, item);
                }

                return;
            }

            string text = value.ToString();
            foreach (string part in text.Split(','))
            {
                string trimmed = part.Trim();
                if (trimmed.Length > 0) result.Add(trimmed);
            }
        }

        private static PortRuleSet PolicyPortSet(object value)
        {
            PortRuleSet result = new PortRuleSet();
            foreach (string port in PolicyStringSet(value))
            {
                result.Add(port);
            }

            return result;
        }

        private static Dictionary<string, PortRuleSet> PolicyProcessPortMap(object value)
        {
            Dictionary<string, PortRuleSet> result = new Dictionary<string, PortRuleSet>(StringComparer.OrdinalIgnoreCase);

            IDictionary map = value as IDictionary;
            if (map != null)
            {
                foreach (DictionaryEntry entry in map)
                {
                    string processName = entry.Key == null ? "" : entry.Key.ToString().Trim();
                    if (processName.Length == 0) continue;

                    result[processName] = PolicyPortSet(entry.Value);
                }

                return result;
            }

            string text = value == null ? "" : value.ToString();
            foreach (string entry in text.Split(';'))
            {
                string trimmed = entry.Trim();
                if (trimmed.Length == 0) continue;

                int equals = trimmed.IndexOf('=');
                if (equals <= 0 || equals >= trimmed.Length - 1) continue;

                string processName = trimmed.Substring(0, equals).Trim();
                string portText = trimmed.Substring(equals + 1).Trim();
                if (processName.Length == 0 || portText.Length == 0) continue;

                result[processName] = PolicyPortSet(portText);
            }

            return result;
        }

        private static HashSet<IPAddress> PolicyIpSet(object value)
        {
            HashSet<IPAddress> result = new HashSet<IPAddress>();
            foreach (string item in PolicyStringSet(value))
            {
                IPAddress address;
                if (IPAddress.TryParse(item, out address))
                {
                    result.Add(address);
                }
            }

            return result;
        }

        private static HashSet<string> PolicyCountrySet(object value)
        {
            HashSet<string> result = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (string item in PolicyStringSet(value))
            {
                string normalized = NormalizeCountryCode(item);
                if (normalized.Length > 0)
                {
                    result.Add(normalized);
                }
            }

            return result;
        }

        public bool IsAllowedDnsResolver(IPAddress address)
        {
            return AllowedDnsResolvers.Contains(address);
        }

        public bool IsAllowedRemoteCountry(string country)
        {
            string normalized = NormalizeCountryCode(country);
            return normalized.Length > 0 && AllowedRemoteCountries.Contains(normalized);
        }

        public static string NormalizeCountryCode(string value)
        {
            if (String.IsNullOrWhiteSpace(value)) return "";

            string trimmed = value.Trim();
            if (trimmed.Equals("USA", StringComparison.OrdinalIgnoreCase) ||
                trimmed.Equals("United States", StringComparison.OrdinalIgnoreCase) ||
                trimmed.Equals("United States of America", StringComparison.OrdinalIgnoreCase))
            {
                return "US";
            }

            if (trimmed.Equals("Canada", StringComparison.OrdinalIgnoreCase)) return "CA";
            if (trimmed.Equals("UK", StringComparison.OrdinalIgnoreCase) ||
                trimmed.Equals("United Kingdom", StringComparison.OrdinalIgnoreCase) ||
                trimmed.Equals("Great Britain", StringComparison.OrdinalIgnoreCase))
            {
                return "GB";
            }

            if (trimmed.Equals("Ireland", StringComparison.OrdinalIgnoreCase)) return "IE";
            if (trimmed.Equals("Germany", StringComparison.OrdinalIgnoreCase)) return "DE";
            if (trimmed.Equals("Netherlands", StringComparison.OrdinalIgnoreCase)) return "NL";
            if (trimmed.Equals("France", StringComparison.OrdinalIgnoreCase)) return "FR";
            if (trimmed.Equals("Sweden", StringComparison.OrdinalIgnoreCase)) return "SE";
            if (trimmed.Equals("Switzerland", StringComparison.OrdinalIgnoreCase)) return "CH";
            if (trimmed.Equals("Australia", StringComparison.OrdinalIgnoreCase)) return "AU";
            if (trimmed.Equals("New Zealand", StringComparison.OrdinalIgnoreCase)) return "NZ";
            if (trimmed.Equals("Japan", StringComparison.OrdinalIgnoreCase)) return "JP";
            if (trimmed.Equals("Singapore", StringComparison.OrdinalIgnoreCase)) return "SG";

            return trimmed.ToUpperInvariant();
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

        public int ExternalAlertProviderMinimumScore(string provider)
        {
            if (ExternalAlertProviderMinimumScores == null || ExternalAlertProviderMinimumScores.Count == 0) return 0;

            string expected = CanonicalExternalAlertProvider(provider);
            foreach (KeyValuePair<string, int> item in ExternalAlertProviderMinimumScores)
            {
                if (CanonicalExternalAlertProvider(item.Key).Equals(expected, StringComparison.OrdinalIgnoreCase))
                {
                    return item.Value;
                }
            }

            return 0;
        }

        public int ExternalAlertProviderHourlyLimit(string provider)
        {
            if (ExternalAlertProviderMaxPerHour == null || ExternalAlertProviderMaxPerHour.Count == 0) return 0;

            string expected = CanonicalExternalAlertProvider(provider);
            foreach (KeyValuePair<string, int> item in ExternalAlertProviderMaxPerHour)
            {
                if (CanonicalExternalAlertProvider(item.Key).Equals(expected, StringComparison.OrdinalIgnoreCase))
                {
                    return item.Value;
                }
            }

            return 0;
        }

        public bool HasExternalAlertProviderEligibleForScore(int score)
        {
            foreach (string provider in GetExternalAlertProviders())
            {
                string canonical = CanonicalExternalAlertProvider(provider);
                if (canonical.Equals("Disabled", StringComparison.OrdinalIgnoreCase)) continue;
                if (ExternalAlertProviderMinimumScore(provider) <= score) return true;
            }

            return false;
        }

        public bool DailyReportDestinationEnabled(string destination)
        {
            if (String.IsNullOrWhiteSpace(destination)) return false;
            if (DailyReportDestinations == null || DailyReportDestinations.Count == 0) return false;
            string expected = CanonicalDailyReportDestination(destination);
            foreach (string configured in DailyReportDestinations)
            {
                if (CanonicalDailyReportDestination(configured).Equals(expected, StringComparison.OrdinalIgnoreCase)) return true;
            }

            return false;
        }

        public static string CanonicalDailyReportDestination(string destination)
        {
            if (destination == null) return "";
            if (destination.Equals("ExternalAlertSinks", StringComparison.OrdinalIgnoreCase)) return "ExternalAlertSinks";
            if (destination.Equals("LocalArchive", StringComparison.OrdinalIgnoreCase)) return "LocalArchive";
            if (destination.Equals("Webhook", StringComparison.OrdinalIgnoreCase)) return "Webhook";
            return destination.Trim();
        }

        public static string CanonicalExternalAlertProvider(string provider)
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

            return provider.Trim();
        }

        public List<string> GetAiAnalysisProviderNames()
        {
            List<string> result = new List<string>();
            foreach (string provider in AIAnalysisProviders)
            {
                if (!String.IsNullOrWhiteSpace(provider)) result.Add(provider.Trim());
            }

            return result;
        }

        public AiAnalysisProviderSettings AiAnalysisSettingsFor(string providerName)
        {
            string configuredName = String.IsNullOrWhiteSpace(providerName) ? "" : providerName.Trim();
            bool singleProvider = GetAiAnalysisProviderNames().Count <= 1;
            string providerType = ProviderMapValueOr(AIAnalysisProviderTypes, configuredName, "");
            if (String.IsNullOrWhiteSpace(providerType)) providerType = configuredName;
            providerType = CanonicalAiAnalysisProvider(providerType);

            AiAnalysisProviderSettings settings = new AiAnalysisProviderSettings();
            settings.ProviderName = configuredName;
            settings.ProviderType = providerType;
            settings.Model = ProviderMapValueOr(AIAnalysisProviderModels, configuredName, singleProvider ? AIAnalysisModel : "");
            settings.ApiUrl = ProviderMapValueOr(AIAnalysisProviderApiUrls, configuredName, singleProvider ? AIAnalysisApiUrl : "");
            settings.ApiKeyEnvironmentVariable = ProviderMapValueOr(AIAnalysisProviderApiKeyEnvironmentVariables, configuredName, singleProvider ? AIAnalysisApiKeyEnvironmentVariable : "");
            settings.AuthHeaderName = ProviderMapValueOr(AIAnalysisProviderAuthHeaderNames, configuredName, singleProvider ? AIAnalysisAuthHeaderName : "");
            settings.AuthHeaderPrefixConfigured = ProviderMapContains(AIAnalysisProviderAuthHeaderPrefixes, configuredName) ||
                (singleProvider && !String.IsNullOrWhiteSpace(AIAnalysisAuthHeaderPrefix));
            settings.AuthHeaderPrefix = ProviderMapValueOr(AIAnalysisProviderAuthHeaderPrefixes, configuredName, singleProvider ? AIAnalysisAuthHeaderPrefix : "");
            settings.VersionHeaderName = ProviderMapValueOr(AIAnalysisProviderVersionHeaderNames, configuredName, "");
            settings.VersionHeaderValue = ProviderMapValueOr(AIAnalysisProviderVersionHeaderValues, configuredName, "");

            ApplyAiProviderDefaults(settings);
            return settings;
        }

        private static void ApplyAiProviderDefaults(AiAnalysisProviderSettings settings)
        {
            if (settings.ProviderType.Equals("OpenAI", StringComparison.OrdinalIgnoreCase))
            {
                if (String.IsNullOrWhiteSpace(settings.ApiUrl)) settings.ApiUrl = "https://api.openai.com/v1/responses";
                if (String.IsNullOrWhiteSpace(settings.ApiKeyEnvironmentVariable)) settings.ApiKeyEnvironmentVariable = "OpenAIAPIKey_ArcaneEDR";
                if (String.IsNullOrWhiteSpace(settings.AuthHeaderName)) settings.AuthHeaderName = "Authorization";
                settings.AuthHeaderPrefix = NormalizeAuthPrefix(settings.AuthHeaderPrefix, settings.AuthHeaderPrefixConfigured, "Bearer ");
                return;
            }

            if (settings.ProviderType.Equals("OpenAICompatible", StringComparison.OrdinalIgnoreCase))
            {
                settings.AuthHeaderPrefix = NormalizeAuthPrefix(settings.AuthHeaderPrefix, settings.AuthHeaderPrefixConfigured, "Bearer ");
                return;
            }

            if (settings.ProviderType.Equals("Anthropic", StringComparison.OrdinalIgnoreCase))
            {
                if (String.IsNullOrWhiteSpace(settings.ApiUrl)) settings.ApiUrl = "https://api.anthropic.com/v1/messages";
                if (String.IsNullOrWhiteSpace(settings.ApiKeyEnvironmentVariable)) settings.ApiKeyEnvironmentVariable = "ANTHROPIC_API_KEY";
                if (String.IsNullOrWhiteSpace(settings.AuthHeaderName)) settings.AuthHeaderName = "x-api-key";
                if (String.IsNullOrWhiteSpace(settings.AuthHeaderPrefix)) settings.AuthHeaderPrefix = "";
                if (String.IsNullOrWhiteSpace(settings.VersionHeaderName)) settings.VersionHeaderName = "anthropic-version";
                if (String.IsNullOrWhiteSpace(settings.VersionHeaderValue)) settings.VersionHeaderValue = "2023-06-01";
            }
        }

        private static string NormalizeAuthPrefix(string value, bool configured, string fallback)
        {
            if (!configured && String.IsNullOrWhiteSpace(value)) return fallback;
            if (value == null) return "";
            if (value.Equals("Bearer", StringComparison.OrdinalIgnoreCase)) return "Bearer ";
            return value;
        }

        public static string CanonicalAiAnalysisProvider(string provider)
        {
            if (provider == null) return "";
            if (provider.Equals("None", StringComparison.OrdinalIgnoreCase) ||
                provider.Equals("Off", StringComparison.OrdinalIgnoreCase))
            {
                return "Disabled";
            }

            if (provider.Equals("Claude", StringComparison.OrdinalIgnoreCase) ||
                provider.Equals("AnthropicClaude", StringComparison.OrdinalIgnoreCase))
            {
                return "Anthropic";
            }

            if (provider.Equals("OpenAIResponses", StringComparison.OrdinalIgnoreCase) ||
                provider.Equals("OpenAICompatibleResponses", StringComparison.OrdinalIgnoreCase) ||
                provider.Equals("Responses", StringComparison.OrdinalIgnoreCase))
            {
                return "OpenAICompatible";
            }

            return provider.Trim();
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

        private static Dictionary<string, PortRuleSet> ReadProcessPortMap(Dictionary<string, string> values, string key)
        {
            Dictionary<string, PortRuleSet> result = new Dictionary<string, PortRuleSet>(StringComparer.OrdinalIgnoreCase);
            string value;
            if (!values.TryGetValue(key, out value)) return result;

            foreach (string entry in value.Split(';'))
            {
                string trimmed = entry.Trim();
                if (trimmed.Length == 0) continue;

                int equals = trimmed.IndexOf('=');
                if (equals <= 0 || equals >= trimmed.Length - 1) continue;

                string processName = trimmed.Substring(0, equals).Trim();
                string portText = trimmed.Substring(equals + 1).Trim();
                if (processName.Length == 0 || portText.Length == 0) continue;

                PortRuleSet ports = new PortRuleSet();
                foreach (string part in portText.Split(','))
                {
                    ports.Add(part.Trim());
                }

                result[processName] = ports;
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

        private static List<string> ReadStringList(Dictionary<string, string> values, string key)
        {
            List<string> result = new List<string>();
            string value;
            if (!values.TryGetValue(key, out value)) return result;
            foreach (string part in value.Split(','))
            {
                string trimmed = part.Trim();
                if (trimmed.Length > 0) result.Add(trimmed);
            }

            return result;
        }

        private static HashSet<string> DefaultLowValueRepeatDampeningCategories()
        {
            return DefaultExternalAlertGroupingCategories();
        }

        private static HashSet<string> DefaultExternalAlertGroupingCategories()
        {
            HashSet<string> result = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            result.Add("Network");
            result.Add("DNS");
            result.Add("Baseline");
            result.Add("Reputation");
            result.Add("Process");
            return result;
        }

        private static HashSet<string> DefaultDailyReportSections()
        {
            HashSet<string> result = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            result.Add("QuickVerdict");
            result.Add("CriticalCallouts");
            result.Add("AtAGlance");
            result.Add("SignalSummary");
            result.Add("FalsePositiveContext");
            result.Add("HighSignalDetails");
            result.Add("AutomationActivity");
            result.Add("AIReview");
            result.Add("TuningNotes");
            return result;
        }

        private static HashSet<string> DefaultDailyReportDestinations()
        {
            HashSet<string> result = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            result.Add("ExternalAlertSinks");
            result.Add("LocalArchive");
            return result;
        }

        private static HashSet<string> DefaultDailyReportArchiveFormats()
        {
            HashSet<string> result = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            result.Add("Markdown");
            result.Add("Json");
            return result;
        }

        private static HashSet<string> DefaultTrustedPersistenceSignerSubjects()
        {
            HashSet<string> result = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            result.Add("Microsoft Windows");
            result.Add("Microsoft Corporation");
            result.Add("Microsoft Windows Publisher");
            return result;
        }

        private static HashSet<string> DefaultAgentAdminCommandTerms()
        {
            HashSet<string> result = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            result.Add("-verb runas");
            result.Add("runas.exe");
            result.Add("schtasks");
            result.Add("start-scheduledtask");
            result.Add("register-scheduledtask");
            result.Add("new-scheduledtask");
            result.Add("run-admin-task.cmd");
            result.Add("run-admin-task.ps1");
            result.Add("admin-task-runner.ps1");
            result.Add("new-service");
            result.Add("sc.exe create");
            result.Add("sc create");
            result.Add("set-service");
            result.Add("netsh advfirewall");
            result.Add("new-netfirewallrule");
            result.Add("set-netfirewallrule");
            result.Add("remove-netfirewallrule");
            result.Add("icacls");
            result.Add("takeown");
            result.Add("set-acl");
            result.Add("reg add");
            result.Add("\\currentversion\\run");
            result.Add("set-mppreference");
            result.Add("add-mppreference");
            result.Add("disableantispyware");
            result.Add("disablerealtimemonitoring");
            return result;
        }

        private static HashSet<string> DefaultAgentSecretReferenceTerms()
        {
            HashSet<string> result = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            result.Add("apikey");
            result.Add("api_key");
            result.Add("access_token");
            result.Add("refresh_token");
            result.Add("client_secret");
            result.Add("private_key");
            result.Add("id_rsa");
            result.Add("id_ed25519");
            result.Add(".pem");
            result.Add(".pfx");
            result.Add(".env");
            result.Add("credentials");
            result.Add("token.json");
            result.Add("aws_access_key_id");
            result.Add("azure_client_secret");
            result.Add("gcloud");
            result.Add("\\appdata\\local\\google\\chrome\\user data");
            result.Add("\\appdata\\local\\microsoft\\edge\\user data");
            result.Add("\\mozilla\\firefox\\profiles");
            return result;
        }

        private static HashSet<string> DefaultAgentSupplyChainTerms()
        {
            HashSet<string> result = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            result.Add("npm install");
            result.Add("npm ci");
            result.Add("npm exec");
            result.Add("npx ");
            result.Add("pnpm install");
            result.Add("yarn install");
            result.Add("pip install");
            result.Add("pip3 install");
            result.Add("python -m pip install");
            result.Add("curl ");
            result.Add("curl.exe");
            result.Add("invoke-webrequest");
            result.Add("wget ");
            result.Add("downloadstring");
            result.Add("downloadfile");
            result.Add("git clone");
            result.Add("invoke-restmethod");
            result.Add("invoke-expression");
            result.Add("install.ps1");
            result.Add("install.sh");
            result.Add("postinstall");
            return result;
        }

        private static HashSet<string> DefaultResponseBlockedRuleIds()
        {
            HashSet<string> result = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            result.Add(AlertRuleTaxonomy.RuleServiceStarted);
            result.Add(AlertRuleTaxonomy.RuleServiceStopped);
            result.Add(AlertRuleTaxonomy.RuleServiceRecoveredAfterUncleanStop);
            result.Add(AlertRuleTaxonomy.RuleTestAlert);
            return result;
        }

        private static HashSet<string> DefaultResponseBlockedCategories()
        {
            HashSet<string> result = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            result.Add("Agent");
            result.Add("AI");
            result.Add("Baseline");
            result.Add("Health");
            result.Add("Response");
            result.Add("Test");
            return result;
        }

        private static HashSet<string> DefaultResponseProtectedProcessNames()
        {
            HashSet<string> result = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            result.Add("System");
            result.Add("Idle");
            result.Add("Registry");
            result.Add("smss.exe");
            result.Add("csrss.exe");
            result.Add("wininit.exe");
            result.Add("winlogon.exe");
            result.Add("services.exe");
            result.Add("lsass.exe");
            result.Add("svchost.exe");
            result.Add("explorer.exe");
            result.Add("dwm.exe");
            result.Add("fontdrvhost.exe");
            result.Add("sihost.exe");
            result.Add("taskhostw.exe");
            result.Add("chrome.exe");
            result.Add("msedge.exe");
            result.Add("firefox.exe");
            result.Add("code.exe");
            result.Add("devenv.exe");
            result.Add("git.exe");
            result.Add("git-remote-https.exe");
            result.Add("codex.exe");
            result.Add("Codex.exe");
            return result;
        }

        private static HashSet<string> DefaultHighRiskFilePathIndicators()
        {
            HashSet<string> result = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            result.Add("\\appdata\\roaming\\microsoft\\windows\\start menu\\programs\\startup\\");
            result.Add("\\programdata\\microsoft\\windows\\start menu\\programs\\startup\\");
            result.Add("\\windows\\system32\\tasks\\");
            result.Add("\\appdata\\local\\google\\chrome\\user data\\default\\extensions\\");
            result.Add("\\appdata\\local\\microsoft\\edge\\user data\\default\\extensions\\");
            return result;
        }

        private static HashSet<string> DefaultHighRiskFileExtensions()
        {
            HashSet<string> result = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            result.Add(".exe");
            result.Add(".dll");
            result.Add(".scr");
            result.Add(".com");
            result.Add(".msi");
            result.Add(".msp");
            result.Add(".ps1");
            result.Add(".psm1");
            result.Add(".vbs");
            result.Add(".vbe");
            result.Add(".js");
            result.Add(".jse");
            result.Add(".hta");
            result.Add(".bat");
            result.Add(".cmd");
            result.Add(".lnk");
            result.Add(".url");
            result.Add(".jar");
            return result;
        }

        private static HashSet<string> DefaultSensitiveFileNameIndicators()
        {
            HashSet<string> result = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            result.Add("apikey");
            result.Add("api_key");
            result.Add("access_token");
            result.Add("refresh_token");
            result.Add("client_secret");
            result.Add("private_key");
            result.Add("id_rsa");
            result.Add("id_ed25519");
            result.Add(".pem");
            result.Add(".pfx");
            result.Add(".env");
            result.Add("credentials");
            result.Add("token.json");
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

        private static Dictionary<string, string> ReadStringMap(Dictionary<string, string> values, string key)
        {
            Dictionary<string, string> result = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
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
                string mapValue = item.Substring(separator + 1).Trim();
                if (name.Length > 0) result[name] = mapValue;
            }

            return result;
        }

        private static string ProviderMapValueOr(Dictionary<string, string> values, string providerName, string fallback)
        {
            string value;
            return TryMapValue(values, providerName, out value) ? value : (fallback ?? "");
        }

        private static bool ProviderMapContains(Dictionary<string, string> values, string providerName)
        {
            string value;
            return TryMapValue(values, providerName, out value);
        }

        private static bool TryMapValue(Dictionary<string, string> values, string providerName, out string value)
        {
            value = "";
            if (values == null || String.IsNullOrWhiteSpace(providerName)) return false;
            if (values.TryGetValue(providerName, out value)) return true;

            string canonical = CanonicalAiAnalysisProvider(providerName);
            foreach (KeyValuePair<string, string> item in values)
            {
                if (CanonicalAiAnalysisProvider(item.Key).Equals(canonical, StringComparison.OrdinalIgnoreCase))
                {
                    value = item.Value;
                    return true;
                }
            }

            return false;
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

        private static HashSet<string> NormalizeExtensions(HashSet<string> values)
        {
            HashSet<string> result = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (string value in values)
            {
                string trimmed = value.Trim();
                if (trimmed.Length == 0) continue;
                if (!trimmed.StartsWith(".", StringComparison.Ordinal)) trimmed = "." + trimmed;
                result.Add(trimmed);
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
