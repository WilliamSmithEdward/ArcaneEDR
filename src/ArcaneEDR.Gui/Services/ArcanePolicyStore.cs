using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;

namespace ArcaneEDR_Gui.Services;

internal sealed class ArcanePolicySnapshot
{
    public string Path { get; set; } = "";
    public string Schema { get; set; } = "";
    public string Description { get; set; } = "";
    public string LoadStatus { get; set; } = "";
    public string RawJson { get; set; } = "";
    public List<ArcanePolicyEntry> Entries { get; } = new List<ArcanePolicyEntry>();

    public string SummaryText
    {
        get
        {
            int enabled = Entries.Count(entry => entry.Enabled);
            return Entries.Count.ToString(System.Globalization.CultureInfo.InvariantCulture) +
                " policy entries loaded; " +
                enabled.ToString(System.Globalization.CultureInfo.InvariantCulture) +
                " enabled.";
        }
    }

    public int CountScope(string scope)
    {
        return Entries.Count(entry => entry.Scope.Equals(scope, StringComparison.OrdinalIgnoreCase));
    }
}

internal sealed class ArcanePolicyEntry
{
    public string Scope { get; set; } = "";
    public string Id { get; set; } = "";
    public bool Enabled { get; set; } = true;
    public string Action { get; set; } = "";
    public string Score { get; set; } = "";
    public string Owner { get; set; } = "";
    public string Reason { get; set; } = "";
    public string MatchSummary { get; set; } = "";
    public string DetailText { get; set; } = "";
    public int ItemCount { get; set; }

    public string EnabledDisplay => Enabled ? "Enabled" : "Disabled";

    public string SearchText =>
        (Scope + " " + Id + " " + EnabledDisplay + " " + Action + " " + Score + " " +
        Owner + " " + Reason + " " + MatchSummary + " " + DetailText).ToLowerInvariant();
}

internal static class ArcanePolicyStore
{
    public static ArcanePolicySnapshot Load()
    {
        string path = ArcanePaths.Discover().PolicyFile;
        ArcanePolicySnapshot snapshot = new ArcanePolicySnapshot
        {
            Path = path
        };

        if (String.IsNullOrWhiteSpace(path) || !File.Exists(path))
        {
            snapshot.LoadStatus = "Policy file not found: " + path;
            return snapshot;
        }

        snapshot.RawJson = File.ReadAllText(path);

        try
        {
            using JsonDocument document = JsonDocument.Parse(snapshot.RawJson);
            JsonElement root = document.RootElement;
            snapshot.Schema = GetString(root, "schema");
            snapshot.Description = GetString(root, "description");
            snapshot.LoadStatus = "Loaded " + path;

            AddPolicySection(snapshot, root, "allowlists", "Allowlist", "allow");
            AddPolicySection(snapshot, root, "blocklists", "Blocklist", "block");
            AddResponsePolicy(snapshot, root);
            AddRuleArray(snapshot, root, "remote_endpoint_policies", "Remote endpoint");
            AddRuleArray(snapshot, root, "detection_policies", "Detection");
        }
        catch (Exception ex)
        {
            snapshot.LoadStatus = "Policy JSON could not be parsed: " + ex.Message;
        }

        return snapshot;
    }

    private static void AddPolicySection(
        ArcanePolicySnapshot snapshot,
        JsonElement root,
        string propertyName,
        string scope,
        string defaultAction)
    {
        if (!TryGetObject(root, propertyName, out JsonElement section))
        {
            return;
        }

        foreach (JsonProperty property in section.EnumerateObject())
        {
            string summary = SummarizeElement(property.Value);
            snapshot.Entries.Add(new ArcanePolicyEntry
            {
                Scope = scope,
                Id = property.Name,
                Enabled = true,
                Action = defaultAction,
                MatchSummary = summary,
                ItemCount = CountElementItems(property.Value),
                Reason = scope + " policy setting from unified policy.",
                DetailText = BuildSettingDetail(scope, property.Name, defaultAction, summary, property.Value)
            });
        }
    }

    private static void AddResponsePolicy(ArcanePolicySnapshot snapshot, JsonElement root)
    {
        if (!TryGetObject(root, "response_policy", out JsonElement response))
        {
            return;
        }

        foreach (JsonProperty property in response.EnumerateObject())
        {
            string action = property.Name.StartsWith("allowed_", StringComparison.OrdinalIgnoreCase)
                ? "allow"
                : property.Name.StartsWith("blocked_", StringComparison.OrdinalIgnoreCase)
                    ? "block"
                    : "protect";
            string summary = SummarizeElement(property.Value);
            snapshot.Entries.Add(new ArcanePolicyEntry
            {
                Scope = "Response",
                Id = property.Name,
                Enabled = true,
                Action = action,
                MatchSummary = summary,
                ItemCount = CountElementItems(property.Value),
                Reason = "Response policy gate from unified policy.",
                DetailText = BuildSettingDetail("Response", property.Name, action, summary, property.Value)
            });
        }
    }

    private static void AddRuleArray(
        ArcanePolicySnapshot snapshot,
        JsonElement root,
        string propertyName,
        string scope)
    {
        if (!root.TryGetProperty(propertyName, out JsonElement rules) ||
            rules.ValueKind != JsonValueKind.Array)
        {
            return;
        }

        int index = 0;
        foreach (JsonElement rule in rules.EnumerateArray())
        {
            index++;
            if (rule.ValueKind != JsonValueKind.Object)
            {
                continue;
            }

            string id = FirstNonEmpty(GetString(rule, "id"), scope.ToLowerInvariant().Replace(" ", "-") + "-" + index.ToString(System.Globalization.CultureInfo.InvariantCulture));
            bool enabled = GetBool(rule, "enabled", true);
            string action = FirstNonEmpty(GetString(rule, "action"), "observe");
            string score = FirstNonEmpty(GetRawString(rule, "score"), GetRawString(rule, "score_delta"));
            string owner = GetString(rule, "owner");
            string reason = GetString(rule, "reason");
            string match = "";
            if (rule.TryGetProperty("match", out JsonElement matchElement))
            {
                match = SummarizeElement(matchElement);
            }

            snapshot.Entries.Add(new ArcanePolicyEntry
            {
                Scope = scope,
                Id = id,
                Enabled = enabled,
                Action = action,
                Score = score,
                Owner = owner,
                Reason = reason,
                MatchSummary = match,
                ItemCount = 1,
                DetailText = BuildRuleDetail(scope, id, enabled, action, score, owner, reason, match, rule)
            });
        }
    }

    private static string BuildSettingDetail(string scope, string id, string action, string summary, JsonElement value)
    {
        return "Scope=" + scope + Environment.NewLine +
            "Id=" + id + Environment.NewLine +
            "Enabled=True" + Environment.NewLine +
            "Action=" + action + Environment.NewLine +
            "Summary=" + summary + Environment.NewLine + Environment.NewLine +
            "JSON=" + Environment.NewLine +
            FormatJson(value);
    }

    private static string BuildRuleDetail(
        string scope,
        string id,
        bool enabled,
        string action,
        string score,
        string owner,
        string reason,
        string match,
        JsonElement rule)
    {
        return "Scope=" + scope + Environment.NewLine +
            "Id=" + id + Environment.NewLine +
            "Enabled=" + enabled + Environment.NewLine +
            "Action=" + action + Environment.NewLine +
            "Score=" + score + Environment.NewLine +
            "Owner=" + owner + Environment.NewLine +
            "Reason=" + reason + Environment.NewLine +
            "Match=" + match + Environment.NewLine + Environment.NewLine +
            "JSON=" + Environment.NewLine +
            FormatJson(rule);
    }

    private static string SummarizeElement(JsonElement element)
    {
        switch (element.ValueKind)
        {
            case JsonValueKind.String:
                return element.GetString() ?? "";
            case JsonValueKind.Number:
            case JsonValueKind.True:
            case JsonValueKind.False:
                return element.ToString();
            case JsonValueKind.Array:
                return SummarizeArray(element);
            case JsonValueKind.Object:
                return SummarizeObject(element);
            case JsonValueKind.Null:
            case JsonValueKind.Undefined:
            default:
                return "";
        }
    }

    private static int CountElementItems(JsonElement element)
    {
        if (element.ValueKind == JsonValueKind.Array)
        {
            return element.GetArrayLength();
        }

        if (element.ValueKind == JsonValueKind.Object)
        {
            return element.EnumerateObject().Count();
        }

        if (element.ValueKind == JsonValueKind.Null || element.ValueKind == JsonValueKind.Undefined)
        {
            return 0;
        }

        return String.IsNullOrWhiteSpace(element.ToString()) ? 0 : 1;
    }

    private static string SummarizeArray(JsonElement element)
    {
        List<string> parts = new List<string>();
        int count = 0;
        foreach (JsonElement child in element.EnumerateArray())
        {
            count++;
            if (parts.Count < 10)
            {
                parts.Add(SummarizeElement(child));
            }
        }

        string summary = String.Join(", ", parts.Where(part => !String.IsNullOrWhiteSpace(part)));
        if (count > parts.Count)
        {
            summary += (summary.Length == 0 ? "" : ", ") + "+" + (count - parts.Count).ToString(System.Globalization.CultureInfo.InvariantCulture) + " more";
        }

        return summary;
    }

    private static string SummarizeObject(JsonElement element)
    {
        List<string> parts = new List<string>();
        int count = 0;
        foreach (JsonProperty property in element.EnumerateObject())
        {
            count++;
            if (parts.Count < 8)
            {
                parts.Add(property.Name + "=" + SummarizeElement(property.Value));
            }
        }

        string summary = String.Join("; ", parts.Where(part => !String.IsNullOrWhiteSpace(part)));
        if (count > parts.Count)
        {
            summary += (summary.Length == 0 ? "" : "; ") + "+" + (count - parts.Count).ToString(System.Globalization.CultureInfo.InvariantCulture) + " more fields";
        }

        return summary;
    }

    private static string FormatJson(JsonElement element)
    {
        return JsonSerializer.Serialize(element, new JsonSerializerOptions
        {
            WriteIndented = true
        });
    }

    private static bool TryGetObject(JsonElement root, string propertyName, out JsonElement value)
    {
        if (root.TryGetProperty(propertyName, out value) && value.ValueKind == JsonValueKind.Object)
        {
            return true;
        }

        value = default;
        return false;
    }

    private static string GetString(JsonElement element, string propertyName)
    {
        if (!element.TryGetProperty(propertyName, out JsonElement value))
        {
            return "";
        }

        return value.ValueKind == JsonValueKind.String ? value.GetString() ?? "" : value.ToString();
    }

    private static string GetRawString(JsonElement element, string propertyName)
    {
        return element.TryGetProperty(propertyName, out JsonElement value) ? value.ToString() : "";
    }

    private static bool GetBool(JsonElement element, string propertyName, bool fallback)
    {
        if (!element.TryGetProperty(propertyName, out JsonElement value))
        {
            return fallback;
        }

        if (value.ValueKind == JsonValueKind.True) return true;
        if (value.ValueKind == JsonValueKind.False) return false;
        if (Boolean.TryParse(value.ToString(), out bool parsed)) return parsed;
        return fallback;
    }

    private static string FirstNonEmpty(params string[] values)
    {
        foreach (string value in values)
        {
            if (!String.IsNullOrWhiteSpace(value))
            {
                return value;
            }
        }

        return "";
    }
}
