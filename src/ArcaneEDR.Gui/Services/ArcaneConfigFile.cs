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

            entries.Add(new ArcaneConfigEntry
            {
                Source = SourceName,
                Key = line.Key,
                Value = line.Value,
                Category = ArcaneConfigCatalog.CategoryFor(line.Key),
                Description = ArcaneConfigCatalog.DescriptionFor(line.Key)
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

        Entries.Add(new ArcaneConfigEntry
        {
            Source = source,
            Key = key,
            Value = value,
            Category = ArcaneConfigCatalog.CategoryFor(key),
            Description = ArcaneConfigCatalog.DescriptionFor(key)
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
        using JsonDocument document = JsonDocument.Parse(json);
        string formatted = JsonSerializer.Serialize(document.RootElement, new JsonSerializerOptions
        {
            WriteIndented = true
        });

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
        using JsonDocument document = JsonDocument.Parse(json);
        return JsonSerializer.Serialize(document.RootElement, new JsonSerializerOptions
        {
            WriteIndented = true
        });
    }
}

internal static class ArcaneConfigCatalog
{
    private static readonly Dictionary<string, string> Descriptions = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
    {
        ["ResponseMode"] = "AlertOnly is safest. Active modes require explicit operator intent.",
        ["MinimumEmailScore"] = "Default external alert threshold.",
        ["ExternalAlertProvider"] = "Disabled, Brevo, Smtp, Webhook, GenericHttpApi, LocalJsonl, WindowsEventLog, or comma-separated providers.",
        ["EnableAIAnalysis"] = "Secondary compact AI review of redacted summaries.",
        ["AIAnalysisApiKeyEnvironmentVariable"] = "Environment variable name only. Do not paste secrets into config.",
        ["EnableRemoteEndpointCountryBlockEnrichment"] = "Local country block lookup before external provider hooks.",
        ["EnableRemoteEndpointIpApiGeolocation"] = "ip-api hook. Off by default; free endpoint is non-commercial only.",
        ["EnableRemoteEndpointIpWhoisGeolocation"] = "ipwhois/ipwho.is hook. Off by default; free endpoint is non-commercial only.",
        ["EnableRemoteEndpointRdapEnrichment"] = "RDAP owner/ASN enrichment for remote endpoints.",
        ["BaselineLearningMode"] = "Initial tuning mode that raises external thresholds for first-seen baseline signals.",
        ["ResponseMinimumScore"] = "Minimum score before response evaluation.",
        ["EnableFirewallBlockResponse"] = "Required before firewall block response modes can act.",
        ["EnableProcessTerminationResponse"] = "Required before process termination response modes can act."
    };

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
        string? description;
        return Descriptions.TryGetValue(key, out description) ? description : "";
    }
}
