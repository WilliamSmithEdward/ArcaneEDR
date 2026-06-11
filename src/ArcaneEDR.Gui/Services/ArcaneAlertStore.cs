using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text.Json;

namespace ArcaneEDR_Gui.Services;

internal sealed class ArcaneAlertRecord
{
    public DateTime TimestampUtc { get; set; }
    public string LocalTime { get; set; } = "";
    public string RuleId { get; set; } = "";
    public string Category { get; set; } = "";
    public string Severity { get; set; } = "";
    public int Score { get; set; }
    public string Title { get; set; } = "";
    public string Process { get; set; } = "";
    public string RemoteIp { get; set; } = "";
    public string Country { get; set; } = "";
    public string Company { get; set; } = "";
    public string PolicyContext { get; set; } = "";
    public bool MaintenanceContext { get; set; }
    public bool ExternalSuppressedByPolicy { get; set; }
    public bool ExternalForcedByPolicy { get; set; }
    public string Recommendation { get; set; } = "";
    public string Entity { get; set; } = "";
    public string Body { get; set; } = "";
    public string RawJson { get; set; } = "";

    public string SystemTimeDisplay
    {
        get
        {
            if (TimestampUtc > DateTime.MinValue)
            {
                DateTime local = TimeZoneInfo.ConvertTimeFromUtc(TimestampUtc, TimeZoneInfo.Local);
                return local.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture);
            }

            return LocalTime;
        }
    }

    public string Summary => String.IsNullOrWhiteSpace(Process)
        ? Title
        : Process + " - " + Title;
}

internal sealed class ArcaneOverviewRecommendation
{
    public string Priority { get; set; } = "";
    public string Title { get; set; } = "";
    public string Detail { get; set; } = "";
}

internal static class ArcaneAlertStore
{
    private static readonly string[] KnownEntityKeys = new[]
    {
        "process",
        "pid",
        "protocol",
        "local",
        "remote",
        "remote_ip",
        "remote_host",
        "rdns",
        "dns_names",
        "sni_hostname",
        "resolved_domain",
        "registrable_domain",
        "asn",
        "asn_org",
        "remote_owner",
        "country",
        "country_lookup",
        "enrichment_source",
        "state",
        "source",
        "process_path",
        "command_line",
        "parent",
        "parent_pid",
        "sha256",
        "signer",
        "policy",
        "agent_context",
        "reasons"
    };

    public static List<ArcaneAlertRecord> ReadAlerts(int maxRows = 2000)
    {
        string path = ArcanePaths.Discover().AlertsFile();
        if (!File.Exists(path)) return new List<ArcaneAlertRecord>();

        string[] lines = File.ReadAllLines(path);
        int start = Math.Max(0, lines.Length - maxRows);
        List<ArcaneAlertRecord> records = new List<ArcaneAlertRecord>();

        for (int index = start; index < lines.Length; index++)
        {
            string line = lines[index];
            if (String.IsNullOrWhiteSpace(line)) continue;

            ArcaneAlertRecord? record = TryParse(line);
            if (record != null)
            {
                records.Add(record);
            }
        }

        records.Sort((left, right) => right.TimestampUtc.CompareTo(left.TimestampUtc));
        return records;
    }

    public static IReadOnlyList<ArcaneOverviewRecommendation> BuildRecommendations(
        IReadOnlyList<ArcaneAlertRecord> alerts,
        ArcaneHealthSnapshot health,
        string validationText)
    {
        List<ArcaneOverviewRecommendation> recommendations = new List<ArcaneOverviewRecommendation>();
        DateTime cutoff = DateTime.UtcNow.AddHours(-24);
        List<ArcaneAlertRecord> recent = alerts.Where(alert => alert.TimestampUtc >= cutoff).ToList();
        List<ArcaneAlertRecord> critical = recent.Where(alert =>
            alert.Score >= 90 ||
            alert.Severity.Equals("critical", StringComparison.OrdinalIgnoreCase)).Take(3).ToList();
        List<ArcaneAlertRecord> high = recent.Where(alert =>
            alert.Score >= 75 &&
            !critical.Contains(alert)).Take(3).ToList();

        if (!health.ServiceState.Equals("Running", StringComparison.OrdinalIgnoreCase))
        {
            recommendations.Add(new ArcaneOverviewRecommendation
            {
                Priority = "Critical",
                Title = "Service is not running",
                Detail = "Review service state before interpreting telemetry gaps."
            });
        }

        if (ArcaneValidationView.HasErrors(validationText))
        {
            recommendations.Add(new ArcaneOverviewRecommendation
            {
                Priority = "High",
                Title = "Configuration validation needs review",
                Detail = ArcaneValidationView.FirstFailureLine(validationText) ?? "Open Configuration and resolve validation errors."
            });
        }

        foreach (ArcaneAlertRecord alert in critical)
        {
            recommendations.Add(new ArcaneOverviewRecommendation
            {
                Priority = "Critical",
                Title = alert.RuleId + " score " + alert.Score,
                Detail = BuildAlertDetail(alert)
            });
        }

        if (critical.Count == 0 && high.Count > 0)
        {
            ArcaneAlertRecord alert = high[0];
            recommendations.Add(new ArcaneOverviewRecommendation
            {
                Priority = "Review",
                Title = alert.RuleId + " score " + alert.Score,
                Detail = BuildAlertDetail(alert)
            });
        }

        var suppressedGroup = recent
            .Where(alert => alert.ExternalSuppressedByPolicy || alert.PolicyContext.IndexOf("suppress", StringComparison.OrdinalIgnoreCase) >= 0)
            .GroupBy(alert => alert.RuleId)
            .OrderByDescending(group => group.Count())
            .FirstOrDefault();
        if (suppressedGroup != null && suppressedGroup.Count() >= 5)
        {
            recommendations.Add(new ArcaneOverviewRecommendation
            {
                Priority = "Tune",
                Title = suppressedGroup.Key + " repeated " + suppressedGroup.Count() + " times",
                Detail = "Suppressed externally but still present locally. Review the Alerts table before widening policy."
            });
        }

        if (recommendations.Count == 0)
        {
            recommendations.Add(new ArcaneOverviewRecommendation
            {
                Priority = "Clear",
                Title = "No high-priority review item in the last 24 hours",
                Detail = "Check Alerts for lower-score baseline activity if you are still tuning this workstation."
            });
        }

        return recommendations.Take(5).ToList();
    }

    private static ArcaneAlertRecord? TryParse(string rawJson)
    {
        try
        {
            using JsonDocument document = JsonDocument.Parse(rawJson);
            JsonElement root = document.RootElement;
            string entity = StringValue(root, "entity");
            string body = StringValue(root, "body");
            string owner = EntityValue(entity, "remote_owner");
            if (String.IsNullOrWhiteSpace(owner))
            {
                owner = EntityValue(entity, "asn_org");
            }

            return new ArcaneAlertRecord
            {
                TimestampUtc = ParseTimestamp(StringValue(root, "timestamp_utc")),
                LocalTime = StringValue(root, "system_local_time"),
                RuleId = StringValue(root, "rule_id"),
                Category = StringValue(root, "category"),
                Severity = StringValue(root, "severity"),
                Score = IntValue(root, "score"),
                Title = StringValue(root, "title"),
                Process = EntityValue(entity, "process"),
                RemoteIp = EntityValue(entity, "remote_ip"),
                Country = EntityValue(entity, "country"),
                Company = owner,
                PolicyContext = StringValue(root, "policy_context"),
                MaintenanceContext = BoolValue(root, "maintenance_context"),
                ExternalSuppressedByPolicy = BoolValue(root, "external_suppressed_by_policy"),
                ExternalForcedByPolicy = BoolValue(root, "external_forced_by_policy"),
                Recommendation = StringValue(root, "recommendation"),
                Entity = entity,
                Body = body,
                RawJson = rawJson
            };
        }
        catch
        {
            return null;
        }
    }

    private static string BuildAlertDetail(ArcaneAlertRecord alert)
    {
        List<string> parts = new List<string>();
        if (!String.IsNullOrWhiteSpace(alert.Title)) parts.Add(alert.Title);
        if (!String.IsNullOrWhiteSpace(alert.Process)) parts.Add("process=" + alert.Process);
        if (!String.IsNullOrWhiteSpace(alert.RemoteIp)) parts.Add("remote=" + alert.RemoteIp);
        if (!String.IsNullOrWhiteSpace(alert.Country)) parts.Add("country=" + alert.Country);
        if (!String.IsNullOrWhiteSpace(alert.Company)) parts.Add("company=" + alert.Company);
        return String.Join("; ", parts);
    }

    private static DateTime ParseTimestamp(string value)
    {
        if (DateTime.TryParse(value, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out DateTime parsed))
        {
            return parsed;
        }

        return DateTime.MinValue;
    }

    private static string StringValue(JsonElement root, string name)
    {
        if (!root.TryGetProperty(name, out JsonElement value)) return "";
        return value.ValueKind == JsonValueKind.String ? value.GetString() ?? "" : value.ToString();
    }

    private static int IntValue(JsonElement root, string name)
    {
        if (!root.TryGetProperty(name, out JsonElement value)) return 0;
        if (value.ValueKind == JsonValueKind.Number && value.TryGetInt32(out int parsed)) return parsed;
        if (Int32.TryParse(value.ToString(), out parsed)) return parsed;
        return 0;
    }

    private static bool BoolValue(JsonElement root, string name)
    {
        if (!root.TryGetProperty(name, out JsonElement value)) return false;
        if (value.ValueKind == JsonValueKind.True) return true;
        if (value.ValueKind == JsonValueKind.False) return false;
        return Boolean.TryParse(value.ToString(), out bool parsed) && parsed;
    }

    private static string EntityValue(string entity, string key)
    {
        if (String.IsNullOrWhiteSpace(entity)) return "";

        string token = key + "=";
        int start = entity.IndexOf(token, StringComparison.OrdinalIgnoreCase);
        if (start < 0) return "";

        start += token.Length;
        int end = entity.Length;
        foreach (string knownKey in KnownEntityKeys)
        {
            string nextToken = " " + knownKey + "=";
            int next = entity.IndexOf(nextToken, start, StringComparison.OrdinalIgnoreCase);
            if (next >= start && next < end)
            {
                end = next;
            }
        }

        return entity.Substring(start, end - start).Trim();
    }
}
