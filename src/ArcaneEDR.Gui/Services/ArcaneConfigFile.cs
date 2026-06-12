using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json;

namespace ArcaneEDR_Gui.Services;

internal sealed class ArcaneConfigEntry : INotifyPropertyChanged
{
    private string value = "";

    public string Source { get; set; } = "";
    public string Key { get; set; } = "";
    public string Category { get; set; } = "";
    public string Description { get; set; } = "";
    public string ValueKind { get; set; } = "";
    public string DangerLevel { get; set; } = "";
    public string RestartRequirement { get; set; } = "";
    public string PrivacyNote { get; set; } = "";
    public string HelpText
    {
        get
        {
            List<string> parts = new List<string>();
            if (!String.IsNullOrWhiteSpace(Description)) parts.Add(Description);
            if (!String.IsNullOrWhiteSpace(ValueKind)) parts.Add("Type: " + ValueKind + ".");
            if (!String.IsNullOrWhiteSpace(DangerLevel) && !DangerLevel.Equals("normal", StringComparison.OrdinalIgnoreCase)) parts.Add("Risk: " + DangerLevel + ".");
            if (!String.IsNullOrWhiteSpace(RestartRequirement)) parts.Add("Applies after: " + RestartRequirement + ".");
            if (!String.IsNullOrWhiteSpace(PrivacyNote)) parts.Add("Privacy: " + PrivacyNote);
            return String.Join(" ", parts);
        }
    }

    public string Value
    {
        get => value;
        set
        {
            if (this.value.Equals(value, StringComparison.Ordinal)) return;
            this.value = value;
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(Value)));
        }
    }

    public event PropertyChangedEventHandler? PropertyChanged;
}

internal sealed class ArcaneConfigFile
{
    private sealed class ConfigLine
    {
        public string Raw { get; set; } = "";
        public string? Key { get; set; }
        public string Value { get; set; } = "";
    }

    private readonly List<ConfigLine> lines = new List<ConfigLine>();
    private readonly Dictionary<string, ConfigLine> byKey = new Dictionary<string, ConfigLine>(StringComparer.OrdinalIgnoreCase);

    public string Path { get; private set; }
    public string SourceName { get; private set; }

    private ArcaneConfigFile(string path, string sourceName)
    {
        Path = path;
        SourceName = sourceName;
    }

    public IReadOnlyDictionary<string, string> Values =>
        byKey.ToDictionary(pair => pair.Key, pair => pair.Value.Value, StringComparer.OrdinalIgnoreCase);

    public static ArcaneConfigFile Load(string path, string sourceName)
    {
        ArcaneConfigFile file = new ArcaneConfigFile(path, sourceName);
        if (!File.Exists(path)) return file;

        foreach (string raw in File.ReadAllLines(path))
        {
            ConfigLine line = ParseLine(raw);
            file.lines.Add(line);
            if (!String.IsNullOrWhiteSpace(line.Key))
            {
                file.byKey[line.Key] = line;
            }
        }

        return file;
    }

    public string Get(string key, string fallback = "")
    {
        ConfigLine? line;
        return byKey.TryGetValue(key, out line) ? line.Value : fallback;
    }

    public bool GetBool(string key, bool fallback)
    {
        string value = Get(key);
        if (Boolean.TryParse(value, out bool parsed)) return parsed;
        return fallback;
    }

    public double GetNumber(string key, double fallback)
    {
        string value = Get(key);
        if (Double.TryParse(value, out double parsed)) return parsed;
        return fallback;
    }

    public void Set(string key, string value)
    {
        if (String.IsNullOrWhiteSpace(key)) return;

        ConfigLine? line;
        if (byKey.TryGetValue(key, out line))
        {
            line.Value = value ?? "";
            return;
        }

        ConfigLine added = new ConfigLine
        {
            Key = key.Trim(),
            Value = value ?? ""
        };
        lines.Add(added);
        byKey[added.Key] = added;
    }

    public ObservableCollection<ArcaneConfigEntry> ToEntries()
    {
        ObservableCollection<ArcaneConfigEntry> entries = new ObservableCollection<ArcaneConfigEntry>();
        foreach (ConfigLine line in lines)
        {
            if (String.IsNullOrWhiteSpace(line.Key)) continue;

            ArcaneConfigMetadata metadata = ArcaneConfigCatalog.MetadataFor(line.Key);
            entries.Add(new ArcaneConfigEntry
            {
                Source = SourceName,
                Key = line.Key,
                Value = line.Value,
                Category = metadata.Category,
                Description = metadata.Description,
                ValueKind = metadata.ValueKind,
                DangerLevel = metadata.DangerLevel,
                RestartRequirement = metadata.RestartRequirement,
                PrivacyNote = metadata.PrivacyNote
            });
        }

        return entries;
    }

    public void ApplyEntries(IEnumerable<ArcaneConfigEntry> entries)
    {
        foreach (ArcaneConfigEntry entry in entries)
        {
            if (entry.Source.Equals(SourceName, StringComparison.OrdinalIgnoreCase))
            {
                Set(entry.Key, entry.Value);
            }
        }
    }

    public string SaveWithBackup()
    {
        if (String.IsNullOrWhiteSpace(Path))
        {
            return "";
        }

        string backup = "";
        if (File.Exists(Path))
        {
            backup = Path + ".gui-backup-" + DateTime.UtcNow.ToString("yyyyMMddHHmmss") + ".bak";
            File.Copy(Path, backup, true);
        }

        string? directory = System.IO.Path.GetDirectoryName(Path);
        if (!String.IsNullOrWhiteSpace(directory))
        {
            Directory.CreateDirectory(directory);
        }

        File.WriteAllLines(Path, lines.Select(SerializeLine), Encoding.ASCII);
        return backup;
    }

    private static ConfigLine ParseLine(string raw)
    {
        string trimmed = raw.Trim();
        if (trimmed.Length == 0 || trimmed.StartsWith("#", StringComparison.Ordinal))
        {
            return new ConfigLine { Raw = raw };
        }

        int equals = raw.IndexOf('=');
        if (equals <= 0)
        {
            return new ConfigLine { Raw = raw };
        }

        return new ConfigLine
        {
            Key = raw.Substring(0, equals).Trim(),
            Value = raw.Substring(equals + 1).Trim()
        };
    }

    private static string SerializeLine(ConfigLine line)
    {
        if (String.IsNullOrWhiteSpace(line.Key)) return line.Raw;
        return line.Key + "=" + line.Value;
    }
}

internal sealed class ArcaneConfigBundle
{
    public ArcaneConfigFile Runtime { get; private set; }
    public ArcaneConfigFile Deployment { get; private set; }
    public ObservableCollection<ArcaneConfigEntry> Entries { get; private set; }

    private ArcaneConfigBundle(
        ArcaneConfigFile runtime,
        ArcaneConfigFile deployment,
        ObservableCollection<ArcaneConfigEntry> entries)
    {
        Runtime = runtime;
        Deployment = deployment;
        Entries = entries;
    }

    public static ArcaneConfigBundle Load()
    {
        ArcanePaths paths = ArcanePaths.Discover();
        ArcaneConfigFile runtime = ArcaneConfigFile.Load(paths.ConfigFile, "Runtime");
        ArcaneConfigFile deployment = ArcaneConfigFile.Load(paths.DeploymentConfigFile, "Deployment");
        ObservableCollection<ArcaneConfigEntry> entries = new ObservableCollection<ArcaneConfigEntry>();

        foreach (ArcaneConfigEntry entry in runtime.ToEntries())
        {
            entries.Add(entry);
        }

        foreach (ArcaneConfigEntry entry in deployment.ToEntries())
        {
            entries.Add(entry);
        }

        return new ArcaneConfigBundle(runtime, deployment, entries);
    }

    public string Save()
    {
        Runtime.ApplyEntries(Entries);
        Deployment.ApplyEntries(Entries);

        List<string> backups = new List<string>();
        string runtimeBackup = Runtime.SaveWithBackup();
        string deploymentBackup = Deployment.SaveWithBackup();
        if (!String.IsNullOrWhiteSpace(runtimeBackup)) backups.Add(runtimeBackup);
        if (!String.IsNullOrWhiteSpace(deploymentBackup)) backups.Add(deploymentBackup);

        return backups.Count == 0
            ? "Saved configuration. No previous files required backups."
            : "Saved configuration. Backups:" + Environment.NewLine + String.Join(Environment.NewLine, backups);
    }

    public void SetEntry(string source, string key, string value)
    {
        ArcaneConfigEntry? existing = Entries.FirstOrDefault(entry =>
            entry.Source.Equals(source, StringComparison.OrdinalIgnoreCase) &&
            entry.Key.Equals(key, StringComparison.OrdinalIgnoreCase));
        if (existing != null)
        {
            existing.Value = value;
            return;
        }

        ArcaneConfigMetadata metadata = ArcaneConfigCatalog.MetadataFor(key);
        Entries.Add(new ArcaneConfigEntry
        {
            Source = source,
            Key = key,
            Value = value,
            Category = metadata.Category,
            Description = metadata.Description,
            ValueKind = metadata.ValueKind,
            DangerLevel = metadata.DangerLevel,
            RestartRequirement = metadata.RestartRequirement,
            PrivacyNote = metadata.PrivacyNote
        });
    }
}

internal static class ArcanePolicyDocument
{
    public static string LoadText()
    {
        string path = ArcanePaths.Discover().PolicyFile;
        return File.Exists(path) ? File.ReadAllText(path) : "";
    }

    public static string SaveFormatted(string json)
    {
        string path = ArcanePaths.Discover().PolicyFile;
        string formatted = GuiJson.Format(json);

        string backup = "";
        if (File.Exists(path))
        {
            backup = path + ".gui-backup-" + DateTime.UtcNow.ToString("yyyyMMddHHmmss") + ".bak";
            File.Copy(path, backup, true);
        }

        File.WriteAllText(path, formatted + Environment.NewLine, Encoding.UTF8);
        return String.IsNullOrWhiteSpace(backup)
            ? "Saved policy JSON."
            : "Saved policy JSON. Backup: " + backup;
    }

    public static string Format(string json)
    {
        return GuiJson.Format(json);
    }
}

internal sealed class ArcaneConfigMetadata
{
    public string Category { get; set; } = "General";
    public string Description { get; set; } = "";
    public string ValueKind { get; set; } = "text";
    public string DangerLevel { get; set; } = "normal";
    public string RestartRequirement { get; set; } = "service restart after save";
    public string PrivacyNote { get; set; } = "";
}

internal static class ArcaneConfigCatalog
{
    private static readonly Dictionary<string, ArcaneConfigMetadata> Metadata = new Dictionary<string, ArcaneConfigMetadata>(StringComparer.OrdinalIgnoreCase)
    {
        ["ResponseMode"] = Meta("Response", "AlertOnly is safest. Active modes require explicit operator intent.", "choice", "dangerous", "service restart after save", ""),
        ["MinimumEmailScore"] = Meta("Alerting", "Default external alert threshold.", "number", "normal", "service restart after save", ""),
        ["ExternalAlertProvider"] = Meta("Alerting", "Disabled, Brevo, Smtp, Webhook, GenericHttpApi, LocalJsonl, WindowsEventLog, or comma-separated providers.", "choice", "privacy", "service restart after save", "May send notifications outside the machine when external providers are enabled."),
        ["EnableAIAnalysis"] = Meta("AI", "Secondary compact AI review of redacted summaries.", "boolean", "privacy", "service restart after save", "May send compact redacted summaries to configured AI providers."),
        ["AIAnalysisApiKeyEnvironmentVariable"] = Meta("AI", "Environment variable name only. Do not paste secrets into config.", "environment variable name", "privacy", "service restart after save", "Stores only the environment variable name."),
        ["AIAnalysisProviderApiKeyEnvironmentVariables"] = Meta("AI", "Provider-to-environment-variable map. Do not paste secrets into config.", "map", "privacy", "service restart after save", "Stores only environment variable names."),
        ["EnableRemoteEndpointCountryBlockEnrichment"] = Meta("Enrichment", "Local country block lookup before external provider hooks.", "boolean", "normal", "service restart after save", "Local lookup only."),
        ["EnableRemoteEndpointIpApiGeolocation"] = Meta("Enrichment", "ip-api hook. Off by default; free endpoint is non-commercial only.", "boolean", "privacy", "service restart after save", "Sends remote IPs to ip-api when enabled."),
        ["EnableRemoteEndpointIpWhoisGeolocation"] = Meta("Enrichment", "ipwhois/ipwho.is hook. Off by default; free endpoint is non-commercial only.", "boolean", "privacy", "service restart after save", "Sends remote IPs to ipwhois/ipwho.is when enabled."),
        ["EnableRemoteEndpointRdapEnrichment"] = Meta("Enrichment", "RDAP owner/ASN enrichment for remote endpoints.", "boolean", "privacy", "service restart after save", "Sends remote IPs to RDAP services when enabled."),
        ["BaselineLearningMode"] = Meta("Baseline", "Initial tuning mode that raises external thresholds for first-seen baseline signals.", "boolean", "normal", "service restart after save", ""),
        ["ResponseMinimumScore"] = Meta("Response", "Minimum score before response evaluation.", "number", "dangerous", "service restart after save", ""),
        ["EnableFirewallBlockResponse"] = Meta("Response", "Required before firewall block response modes can act.", "boolean", "dangerous", "service restart after save", "Can change local firewall state when active response is enabled."),
        ["EnableProcessTerminationResponse"] = Meta("Response", "Required before process termination response modes can act.", "boolean", "dangerous", "service restart after save", "Can terminate processes when active response is enabled."),
        ["PolicyFile"] = Meta("Policy", "Unified JSON policy file.", "path", "normal", "service restart after save", ""),
        ["LogDirectory"] = Meta("Storage", "Mutable local evidence directory.", "path", "normal", "service restart after save", "Contains local security evidence."),
        ["DestinationRoot"] = Meta("Deployment", "Deployment destination root.", "path", "installer", "publish or reinstall", "")
    };

    public static ArcaneConfigMetadata MetadataFor(string key)
    {
        ArcaneConfigMetadata? metadata;
        if (Metadata.TryGetValue(key, out metadata)) return metadata;

        return new ArcaneConfigMetadata
        {
            Category = CategoryFor(key),
            Description = "",
            ValueKind = GuessValueKind(key),
            DangerLevel = GuessDangerLevel(key),
            RestartRequirement = "service restart after save",
            PrivacyNote = GuessPrivacyNote(key)
        };
    }

    public static string CategoryFor(string key)
    {
        if (key.StartsWith("AIAnalysis", StringComparison.OrdinalIgnoreCase) ||
            key.StartsWith("EnableAI", StringComparison.OrdinalIgnoreCase))
        {
            return "AI";
        }

        if (key.Contains("RemoteEndpoint", StringComparison.OrdinalIgnoreCase) ||
            key.Contains("Country", StringComparison.OrdinalIgnoreCase) ||
            key.Contains("Dns", StringComparison.OrdinalIgnoreCase) ||
            key.Contains("Rdap", StringComparison.OrdinalIgnoreCase) ||
            key.Contains("IpApi", StringComparison.OrdinalIgnoreCase) ||
            key.Contains("IpWhois", StringComparison.OrdinalIgnoreCase))
        {
            return "Enrichment";
        }

        if (key.Contains("Alert", StringComparison.OrdinalIgnoreCase) ||
            key.Contains("Brevo", StringComparison.OrdinalIgnoreCase) ||
            key.Contains("Smtp", StringComparison.OrdinalIgnoreCase) ||
            key.Contains("Webhook", StringComparison.OrdinalIgnoreCase) ||
            key.Contains("DailyReport", StringComparison.OrdinalIgnoreCase) ||
            key.Contains("DailySummary", StringComparison.OrdinalIgnoreCase))
        {
            return "Alerting";
        }

        if (key.Contains("Baseline", StringComparison.OrdinalIgnoreCase))
        {
            return "Baseline";
        }

        if (key.Contains("Agent", StringComparison.OrdinalIgnoreCase))
        {
            return "Agent";
        }

        if (key.Contains("Response", StringComparison.OrdinalIgnoreCase))
        {
            return "Response";
        }

        if (key.Contains("Sysmon", StringComparison.OrdinalIgnoreCase) ||
            key.Contains("Event", StringComparison.OrdinalIgnoreCase) ||
            key.Contains("Collector", StringComparison.OrdinalIgnoreCase) ||
            key.Contains("Ingestion", StringComparison.OrdinalIgnoreCase))
        {
            return "Telemetry";
        }

        if (key.Contains("Service", StringComparison.OrdinalIgnoreCase) ||
            key.Contains("Application", StringComparison.OrdinalIgnoreCase) ||
            key.Contains("Destination", StringComparison.OrdinalIgnoreCase) ||
            key.Contains("Executable", StringComparison.OrdinalIgnoreCase))
        {
            return "Deployment";
        }

        return "General";
    }

    public static string DescriptionFor(string key)
    {
        return MetadataFor(key).Description;
    }

    private static ArcaneConfigMetadata Meta(string category, string description, string valueKind, string dangerLevel, string restartRequirement, string privacyNote)
    {
        return new ArcaneConfigMetadata
        {
            Category = category,
            Description = description,
            ValueKind = valueKind,
            DangerLevel = dangerLevel,
            RestartRequirement = restartRequirement,
            PrivacyNote = privacyNote
        };
    }

    private static string GuessValueKind(string key)
    {
        if (key.StartsWith("Enable", StringComparison.OrdinalIgnoreCase) ||
            key.StartsWith("Notify", StringComparison.OrdinalIgnoreCase) ||
            key.EndsWith("Mode", StringComparison.OrdinalIgnoreCase))
        {
            return "boolean or choice";
        }

        if (key.Contains("Score", StringComparison.OrdinalIgnoreCase) ||
            key.Contains("Seconds", StringComparison.OrdinalIgnoreCase) ||
            key.Contains("Minutes", StringComparison.OrdinalIgnoreCase) ||
            key.Contains("Hours", StringComparison.OrdinalIgnoreCase) ||
            key.Contains("Max", StringComparison.OrdinalIgnoreCase))
        {
            return "number";
        }

        if (key.Contains("Path", StringComparison.OrdinalIgnoreCase) ||
            key.Contains("Directory", StringComparison.OrdinalIgnoreCase) ||
            key.Contains("File", StringComparison.OrdinalIgnoreCase) ||
            key.Contains("Root", StringComparison.OrdinalIgnoreCase))
        {
            return "path";
        }

        return "text";
    }

    private static string GuessDangerLevel(string key)
    {
        if (key.Contains("Response", StringComparison.OrdinalIgnoreCase) ||
            key.Contains("Firewall", StringComparison.OrdinalIgnoreCase) ||
            key.Contains("Terminate", StringComparison.OrdinalIgnoreCase))
        {
            return "dangerous";
        }

        if (key.Contains("AI", StringComparison.OrdinalIgnoreCase) ||
            key.Contains("Webhook", StringComparison.OrdinalIgnoreCase) ||
            key.Contains("Smtp", StringComparison.OrdinalIgnoreCase) ||
            key.Contains("Brevo", StringComparison.OrdinalIgnoreCase) ||
            key.Contains("IpApi", StringComparison.OrdinalIgnoreCase) ||
            key.Contains("IpWhois", StringComparison.OrdinalIgnoreCase) ||
            key.Contains("Rdap", StringComparison.OrdinalIgnoreCase))
        {
            return "privacy";
        }

        return "normal";
    }

    private static string GuessPrivacyNote(string key)
    {
        string danger = GuessDangerLevel(key);
        if (danger.Equals("privacy", StringComparison.OrdinalIgnoreCase))
        {
            return "May use external providers depending on the configured value.";
        }

        return "";
    }
}
