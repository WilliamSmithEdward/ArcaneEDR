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
    public string AlertId { get; set; } = "";
    public bool ExternalNotificationSent { get; set; }
    public string ExternalNotificationStatus { get; set; } = "";
    public string ExternalNotificationReason { get; set; } = "";
    public string ExternalNotificationProvider { get; set; } = "";
    public string Recommendation { get; set; } = "";
    public string Entity { get; set; } = "";
    public string Body { get; set; } = "";
    public string RawJson { get; set; } = "";
    public Dictionary<string, string> Metadata { get; set; } = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

    public string MetadataValue(string key)
    {
        return Metadata.TryGetValue(key, out string? value) ? value : "";
    }

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

    public string ExternalNotificationGlyph
    {
        get
        {
            string status = ExternalNotificationStatus ?? "";
            if (ExternalNotificationSent || status.Equals("sent", StringComparison.OrdinalIgnoreCase)) return "\uE7ED";
            if (status.Equals("grouped", StringComparison.OrdinalIgnoreCase)) return "\uE8F2";
            if (String.IsNullOrWhiteSpace(status) || status.Equals("not_recorded", StringComparison.OrdinalIgnoreCase)) return "\uE9CE";
            return "\uE7F4";
        }
    }

    public string ExternalNotificationDisplay
    {
        get
        {
            string label = ExternalNotificationStatusLabel;
            List<string> parts = new List<string> { label };
            if (!String.IsNullOrWhiteSpace(ExternalNotificationProvider)) parts.Add("provider=" + ExternalNotificationProvider);
            if (!String.IsNullOrWhiteSpace(ExternalNotificationReason)) parts.Add(ExternalNotificationReason);
            return String.Join(Environment.NewLine, parts);
        }
    }

    public string ExternalNotificationStatusLabel
    {
        get
        {
            string status = ExternalNotificationStatus ?? "";
            if (ExternalNotificationSent || status.Equals("sent", StringComparison.OrdinalIgnoreCase)) return "Notification sent";
            if (status.Equals("grouped", StringComparison.OrdinalIgnoreCase)) return "Grouped into one notification";
            if (status.Equals("queued", StringComparison.OrdinalIgnoreCase)) return "Notification queued";
            if (status.Equals("below_threshold", StringComparison.OrdinalIgnoreCase)) return "No notification: below threshold";
            if (status.Equals("baseline_learning", StringComparison.OrdinalIgnoreCase)) return "No notification: baseline learning";
            if (status.Equals("suppressed_by_policy", StringComparison.OrdinalIgnoreCase)) return "No notification: policy suppressed";
            if (status.Equals("suppression_group", StringComparison.OrdinalIgnoreCase)) return "No notification: suppression group";
            if (status.Equals("maintenance_threshold", StringComparison.OrdinalIgnoreCase)) return "No notification: maintenance threshold";
            if (status.Equals("response_threshold", StringComparison.OrdinalIgnoreCase)) return "No notification: response threshold";
            if (status.Equals("dampened", StringComparison.OrdinalIgnoreCase)) return "No notification: repeated alert dampened";
            if (status.Equals("per_dispatch_limit", StringComparison.OrdinalIgnoreCase)) return "No notification: dispatch limit";
            if (status.Equals("hourly_limit", StringComparison.OrdinalIgnoreCase)) return "No notification: hourly limit";
            if (status.Equals("provider_unavailable", StringComparison.OrdinalIgnoreCase)) return "No notification: provider unavailable";
            if (status.Equals("skipped_by_sink", StringComparison.OrdinalIgnoreCase)) return "No notification: provider skipped";
            if (status.Equals("failed", StringComparison.OrdinalIgnoreCase)) return "Notification failed";
            if (String.IsNullOrWhiteSpace(status) || status.Equals("not_recorded", StringComparison.OrdinalIgnoreCase)) return "Notification status not recorded";
            return "Notification status: " + status;
        }
    }
}

internal sealed class ArcaneNotificationOutcome
{
    public DateTime TimestampUtc { get; set; }
    public bool Sent { get; set; }
    public string Status { get; set; } = "";
    public string Reason { get; set; } = "";
    public string Provider { get; set; } = "";
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
        ArcanePaths paths = ArcanePaths.Discover();
        string path = paths.AlertsFile();
        if (!File.Exists(path)) return new List<ArcaneAlertRecord>();

        Dictionary<string, ArcaneNotificationOutcome> notificationOutcomes = ReadNotificationOutcomes(paths);
        string[] lines = File.ReadAllLines(path);
        int start = Math.Max(0, lines.Length - maxRows);
        List<ArcaneAlertRecord> records = new List<ArcaneAlertRecord>();

        for (int index = start; index < lines.Length; index++)
        {
            string line = lines[index];
            if (String.IsNullOrWhiteSpace(line)) continue;

            ArcaneAlertRecord? record = TryParse(line, notificationOutcomes);
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
        ArcaneValidationReport validation)
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

        if (validation.ErrorCount > 0)
        {
            recommendations.Add(new ArcaneOverviewRecommendation
            {
                Priority = "High",
                Title = "Configuration validation needs review",
                Detail = ArcaneValidationView.FirstFailureLine(validation) ?? "Open Configuration and resolve validation errors."
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

    private static ArcaneAlertRecord? TryParse(string rawJson, Dictionary<string, ArcaneNotificationOutcome> notificationOutcomes)
    {
        try
        {
            using JsonDocument document = JsonDocument.Parse(rawJson);
            JsonElement root = document.RootElement;
            string entity = StringValue(root, "entity");
            string body = StringValue(root, "body");
            Dictionary<string, string> metadata = EntityMetadata(entity);
            string owner = MetadataValue(metadata, "remote_owner");
            if (String.IsNullOrWhiteSpace(owner))
            {
                owner = MetadataValue(metadata, "asn_org");
            }

            ArcaneAlertRecord record = new ArcaneAlertRecord
            {
                AlertId = StringValue(root, "alert_id"),
                TimestampUtc = ParseTimestamp(StringValue(root, "timestamp_utc")),
                LocalTime = StringValue(root, "system_local_time"),
                RuleId = StringValue(root, "rule_id"),
                Category = StringValue(root, "category"),
                Severity = StringValue(root, "severity"),
                Score = IntValue(root, "score"),
                Title = StringValue(root, "title"),
                Process = MetadataValue(metadata, "process"),
                RemoteIp = MetadataValue(metadata, "remote_ip"),
                Country = MetadataValue(metadata, "country"),
                Company = owner,
                PolicyContext = StringValue(root, "policy_context"),
                MaintenanceContext = BoolValue(root, "maintenance_context"),
                ExternalSuppressedByPolicy = BoolValue(root, "external_suppressed_by_policy"),
                ExternalForcedByPolicy = BoolValue(root, "external_forced_by_policy"),
                ExternalNotificationSent = BoolValue(root, "external_notification_sent"),
                ExternalNotificationStatus = StringValue(root, "external_notification_status"),
                ExternalNotificationReason = StringValue(root, "external_notification_reason"),
                Recommendation = StringValue(root, "recommendation"),
                Entity = entity,
                Body = body,
                RawJson = rawJson,
                Metadata = metadata
            };

            ApplyNotificationOutcome(record, notificationOutcomes);
            return record;
        }
        catch
        {
            return null;
        }
    }

    private static Dictionary<string, ArcaneNotificationOutcome> ReadNotificationOutcomes(ArcanePaths paths)
    {
        Dictionary<string, ArcaneNotificationOutcome> outcomes = new Dictionary<string, ArcaneNotificationOutcome>(StringComparer.OrdinalIgnoreCase);
        string path = Path.Combine(paths.LogDirectory, "ArcaneAlertNotifications.jsonl");
        if (!File.Exists(path)) return outcomes;

        foreach (string line in File.ReadAllLines(path))
        {
            ArcaneNotificationOutcome? outcome = TryParseNotificationOutcome(line, out string alertId);
            if (outcome == null || String.IsNullOrWhiteSpace(alertId)) continue;

            if (!outcomes.TryGetValue(alertId, out ArcaneNotificationOutcome? existing) ||
                outcome.TimestampUtc >= existing.TimestampUtc)
            {
                outcomes[alertId] = outcome;
            }
        }

        return outcomes;
    }

    private static ArcaneNotificationOutcome? TryParseNotificationOutcome(string rawJson, out string alertId)
    {
        alertId = "";
        if (String.IsNullOrWhiteSpace(rawJson)) return null;

        try
        {
            using JsonDocument document = JsonDocument.Parse(rawJson);
            JsonElement root = document.RootElement;
            alertId = StringValue(root, "alert_id");
            return new ArcaneNotificationOutcome
            {
                TimestampUtc = ParseTimestamp(StringValue(root, "timestamp_utc")),
                Sent = BoolValue(root, "sent"),
                Status = StringValue(root, "status"),
                Reason = StringValue(root, "reason"),
                Provider = StringValue(root, "provider")
            };
        }
        catch
        {
            return null;
        }
    }

    private static void ApplyNotificationOutcome(ArcaneAlertRecord record, Dictionary<string, ArcaneNotificationOutcome> outcomes)
    {
        if (record == null) return;

        if (!String.IsNullOrWhiteSpace(record.AlertId) &&
            outcomes != null &&
            outcomes.TryGetValue(record.AlertId, out ArcaneNotificationOutcome? outcome))
        {
            record.ExternalNotificationSent = outcome.Sent;
            record.ExternalNotificationStatus = outcome.Status;
            record.ExternalNotificationReason = outcome.Reason;
            record.ExternalNotificationProvider = outcome.Provider;
            return;
        }

        if (!String.IsNullOrWhiteSpace(record.ExternalNotificationStatus)) return;

        if (record.ExternalSuppressedByPolicy)
        {
            record.ExternalNotificationStatus = "suppressed_by_policy";
            record.ExternalNotificationReason = "Detection policy suppressed external delivery.";
            return;
        }

        record.ExternalNotificationStatus = "not_recorded";
        record.ExternalNotificationReason = "This alert was written before notification outcome tracking was available, or no delivery outcome has been recorded yet.";
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

    private static Dictionary<string, string> EntityMetadata(string entity)
    {
        Dictionary<string, string> metadata = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (string key in KnownEntityKeys)
        {
            string value = EntityValue(entity, key);
            if (!String.IsNullOrWhiteSpace(value))
            {
                metadata[key] = value;
            }
        }

        string remote = MetadataValue(metadata, "remote");
        if (!String.IsNullOrWhiteSpace(remote))
        {
            string remoteIp = MetadataValue(metadata, "remote_ip");
            string port = ExtractPort(remote, remoteIp);
            if (!String.IsNullOrWhiteSpace(port))
            {
                metadata["remote_port"] = port;
            }
        }

        return metadata;
    }

    private static string MetadataValue(Dictionary<string, string> metadata, string key)
    {
        return metadata.TryGetValue(key, out string? value) ? value : "";
    }

    private static string ExtractPort(string remote, string remoteIp)
    {
        string value = remote.Trim();
        if (value.Length == 0) return "";

        int colon = value.LastIndexOf(':');
        if (colon < 0 || colon >= value.Length - 1) return "";

        string candidate = value.Substring(colon + 1);
        if (!Int32.TryParse(candidate, NumberStyles.Integer, CultureInfo.InvariantCulture, out int port))
        {
            return "";
        }

        if (port < 0 || port > 65535) return "";

        if (!String.IsNullOrWhiteSpace(remoteIp) &&
            value.StartsWith(remoteIp + ":", StringComparison.OrdinalIgnoreCase))
        {
            return port.ToString(CultureInfo.InvariantCulture);
        }

        return port.ToString(CultureInfo.InvariantCulture);
    }
}
