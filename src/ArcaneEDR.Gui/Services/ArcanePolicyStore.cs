using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Text.Json.Nodes;

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
    public string SectionName { get; set; } = "";
    public string Id { get; set; } = "";
    public bool Enabled { get; set; } = true;
    public string Action { get; set; } = "";
    public string Score { get; set; } = "";
    public string ScoreDelta { get; set; } = "";
    public string Owner { get; set; } = "";
    public string Tag { get; set; } = "";
    public string ExpiresUtc { get; set; } = "";
    public string Reason { get; set; } = "";
    public string MatchSummary { get; set; } = "";
    public string MatchJson { get; set; } = "{}";
    public string ValueJson { get; set; } = "";
    public string DetailText { get; set; } = "";
    public int ItemCount { get; set; }
    public bool IsRule { get; set; }
    public int SectionIndex { get; set; } = -1;
    public int RuleIndex { get; set; } = -1;
    public int PriorityNumber { get; set; }
    public int DisplayOrder { get; set; }

    public string EnabledDisplay => Enabled ? "Enabled" : "Disabled";
    public string PriorityDisplay => DisplayOrder > 0 ? DisplayOrder.ToString(System.Globalization.CultureInfo.InvariantCulture) : "";
    public int PrioritySort => DisplayOrder;
    public string TypeDisplay => PolicyScopeCatalog.DisplayNameForScope(Scope);

    public string SearchText =>
        (Scope + " " + SectionName + " " + Id + " " + PriorityDisplay + " " +
        EnabledDisplay + " " + Action + " " + Score + " " + ScoreDelta + " " +
        Owner + " " + Tag + " " + ExpiresUtc + " " + Reason + " " + MatchSummary + " " +
        DetailText).ToLowerInvariant();

}

internal sealed class ArcanePolicyEditRequest
{
    public string Scope { get; set; } = "";
    public string SectionName { get; set; } = "";
    public bool IsRule { get; set; }
    public bool IsNew { get; set; }
    public int RuleIndex { get; set; } = -1;
    public string OriginalId { get; set; } = "";
    public string Id { get; set; } = "";
    public bool Enabled { get; set; } = true;
    public string Action { get; set; } = "";
    public string Score { get; set; } = "";
    public string ScoreDelta { get; set; } = "";
    public string Owner { get; set; } = "";
    public string Tag { get; set; } = "";
    public string ExpiresUtc { get; set; } = "";
    public string Reason { get; set; } = "";
    public string MatchJson { get; set; } = "{}";
    public string ValueJson { get; set; } = "";
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
            AssignDisplayOrder(snapshot);
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

        int index = 0;
        foreach (JsonProperty property in section.EnumerateObject())
        {
            index++;
            string summary = SummarizeElement(property.Value);
            snapshot.Entries.Add(new ArcanePolicyEntry
            {
                Scope = scope,
                SectionName = propertyName,
                Id = property.Name,
                Enabled = true,
                Action = defaultAction,
                MatchSummary = summary,
                ValueJson = FormatJson(property.Value),
                ItemCount = CountElementItems(property.Value),
                IsRule = false,
                SectionIndex = index - 1,
                PriorityNumber = index,
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

        int index = 0;
        foreach (JsonProperty property in response.EnumerateObject())
        {
            index++;
            string action = property.Name.StartsWith("allowed_", StringComparison.OrdinalIgnoreCase)
                ? "allow"
                : property.Name.StartsWith("blocked_", StringComparison.OrdinalIgnoreCase)
                    ? "block"
                    : "protect";
            string summary = SummarizeElement(property.Value);
            snapshot.Entries.Add(new ArcanePolicyEntry
            {
                Scope = "Response",
                SectionName = "response_policy",
                Id = property.Name,
                Enabled = true,
                Action = action,
                MatchSummary = summary,
                ValueJson = FormatJson(property.Value),
                ItemCount = CountElementItems(property.Value),
                IsRule = false,
                SectionIndex = index - 1,
                PriorityNumber = index,
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
            string score = GetRawString(rule, "score");
            string scoreDelta = GetRawString(rule, "score_delta");
            string owner = GetString(rule, "owner");
            string tag = GetString(rule, "tag");
            string expiresUtc = GetString(rule, "expires_utc");
            string reason = GetString(rule, "reason");
            string match = "";
            string matchJson = "{}";
            if (rule.TryGetProperty("match", out JsonElement matchElement))
            {
                match = SummarizeElement(matchElement);
                matchJson = FormatJson(matchElement);
            }

            snapshot.Entries.Add(new ArcanePolicyEntry
            {
                Scope = scope,
                SectionName = propertyName,
                Id = id,
                Enabled = enabled,
                Action = action,
                Score = score,
                ScoreDelta = scoreDelta,
                Owner = owner,
                Tag = tag,
                ExpiresUtc = expiresUtc,
                Reason = reason,
                MatchSummary = match,
                MatchJson = matchJson,
                ItemCount = 1,
                IsRule = true,
                SectionIndex = index - 1,
                RuleIndex = index - 1,
                PriorityNumber = index,
                DetailText = BuildRuleDetail(scope, index, id, enabled, action, score, scoreDelta, owner, tag, expiresUtc, reason, match, rule)
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
        int priority,
        string id,
        bool enabled,
        string action,
        string score,
        string scoreDelta,
        string owner,
        string tag,
        string expiresUtc,
        string reason,
        string match,
        JsonElement rule)
    {
        return "Scope=" + scope + Environment.NewLine +
            "Order=" + priority.ToString(System.Globalization.CultureInfo.InvariantCulture) + " within type" + Environment.NewLine +
            "Id=" + id + Environment.NewLine +
            "Enabled=" + enabled + Environment.NewLine +
            "Action=" + action + Environment.NewLine +
            "Score=" + score + Environment.NewLine +
            "ScoreDelta=" + scoreDelta + Environment.NewLine +
            "Owner=" + owner + Environment.NewLine +
            "Tag=" + tag + Environment.NewLine +
            "ExpiresUtc=" + expiresUtc + Environment.NewLine +
            "Reason=" + reason + Environment.NewLine +
            "Match=" + match + Environment.NewLine + Environment.NewLine +
            "JSON=" + Environment.NewLine +
            FormatJson(rule);
    }

    public static string SaveEdit(ArcanePolicyEditRequest request)
    {
        if (request == null)
        {
            throw new ArgumentNullException(nameof(request));
        }

        JsonObject root = LoadRootObject();
        if (request.IsRule || IsRuleScope(request.Scope))
        {
            SaveRuleEdit(root, request);
        }
        else
        {
            SaveSettingEdit(root, request);
        }

        return SaveRoot(root);
    }

    public static string DeleteEntry(ArcanePolicyEntry entry)
    {
        if (entry == null)
        {
            return "No policy entry selected.";
        }

        JsonObject root = LoadRootObject();
        if (entry.IsRule)
        {
            JsonArray rules = GetRuleArray(root, entry.SectionName, create: false);
            if (entry.RuleIndex < 0 || entry.RuleIndex >= rules.Count)
            {
                throw new InvalidOperationException("Selected policy rule no longer exists.");
            }

            rules.RemoveAt(entry.RuleIndex);
        }
        else
        {
            JsonObject section = GetObjectSection(root, entry.SectionName, create: false);
            if (!section.Remove(entry.Id))
            {
                throw new InvalidOperationException("Selected policy setting no longer exists.");
            }
        }

        return SaveRoot(root);
    }

    public static string MoveEntry(ArcanePolicyEntry entry, int delta)
    {
        if (entry == null)
        {
            return "Select a policy entry to change order.";
        }

        JsonObject root = LoadRootObject();
        if (!entry.IsRule)
        {
            JsonObject section = GetObjectSection(root, entry.SectionName, create: false);
            List<KeyValuePair<string, JsonNode?>> items = section.ToList();
            int currentIndex = entry.SectionIndex;
            if (currentIndex < 0 || currentIndex >= items.Count ||
                !items[currentIndex].Key.Equals(entry.Id, StringComparison.OrdinalIgnoreCase))
            {
                currentIndex = items.FindIndex(item => item.Key.Equals(entry.Id, StringComparison.OrdinalIgnoreCase));
            }

            int nextIndex = currentIndex + delta;
            if (currentIndex < 0 || nextIndex < 0 || nextIndex >= items.Count)
            {
                return "Policy entry is already at that order edge.";
            }

            List<KeyValuePair<string, JsonNode?>> reordered = items
                .Select(item => new KeyValuePair<string, JsonNode?>(item.Key, CloneNode(item.Value)))
                .ToList();
            KeyValuePair<string, JsonNode?> movingSetting = reordered[currentIndex];
            reordered.RemoveAt(currentIndex);
            reordered.Insert(nextIndex, movingSetting);

            section.Clear();
            foreach (KeyValuePair<string, JsonNode?> item in reordered)
            {
                section[item.Key] = item.Value;
            }

            return SaveRoot(root);
        }

        JsonArray rules = GetRuleArray(root, entry.SectionName, create: false);
        int nextRuleIndex = entry.RuleIndex + delta;
        if (entry.RuleIndex < 0 || entry.RuleIndex >= rules.Count || nextRuleIndex < 0 || nextRuleIndex >= rules.Count)
        {
            return "Policy entry is already at that order edge.";
        }

        JsonNode? moving = CloneNode(rules[entry.RuleIndex]);
        rules.RemoveAt(entry.RuleIndex);
        rules.Insert(nextRuleIndex, moving);
        return SaveRoot(root);
    }

    public static string FormatMatchJson(string json)
    {
        JsonNode? node = ParseJsonNode(String.IsNullOrWhiteSpace(json) ? "{}" : json, "Match JSON");
        if (node is not JsonObject)
        {
            throw new InvalidOperationException("Match JSON must be an object.");
        }

        return node.ToJsonString(GuiJson.IndentedOptions);
    }

    public static string DefaultMatchJsonForScope(string scope)
    {
        return PolicyScopeCatalog.DefaultMatchJsonForScope(scope);
    }

    public static string DefaultValueJsonForScope(string scope)
    {
        return PolicyScopeCatalog.DefaultValueJsonForScope(scope);
    }

    public static string DefaultActionForScope(string scope)
    {
        return PolicyScopeCatalog.DefaultActionForScope(scope);
    }

    public static IReadOnlyList<string> ActionsForScope(string scope)
    {
        return PolicyScopeCatalog.ActionsForScope(scope);
    }

    public static bool IsRuleScope(string scope)
    {
        return PolicyScopeCatalog.IsRuleScope(scope);
    }

    public static string SectionNameForScope(string scope)
    {
        return PolicyScopeCatalog.SectionNameForScope(scope);
    }

    private static void SaveRuleEdit(JsonObject root, ArcanePolicyEditRequest request)
    {
        string sectionName = FirstNonEmpty(request.SectionName, SectionNameForScope(request.Scope));
        if (String.IsNullOrWhiteSpace(sectionName))
        {
            throw new InvalidOperationException("Choose a rule scope before saving.");
        }

        JsonArray rules = GetRuleArray(root, sectionName, create: true);
        JsonObject rule = ExistingRuleObject(rules, request);
        string id = request.Id.Trim();
        if (String.IsNullOrWhiteSpace(id))
        {
            id = (request.Scope.Equals("Detection", StringComparison.OrdinalIgnoreCase) ? "local-detection-" : "local-remote-endpoint-") +
                DateTime.UtcNow.ToString("yyyyMMddHHmmss");
        }

        SetString(rule, "id", id, required: true);
        rule["enabled"] = request.Enabled;
        SetString(rule, "action", request.Action, required: true);
        SetString(rule, "reason", request.Reason, required: false);
        SetNumber(rule, "score", request.Score, removeWhenBlank: true);

        if (sectionName.Equals("detection_policies", StringComparison.OrdinalIgnoreCase))
        {
            SetNumber(rule, "score_delta", request.ScoreDelta, removeWhenBlank: true);
            SetString(rule, "owner", request.Owner, required: false);
            SetString(rule, "tag", request.Tag, required: false);
            SetString(rule, "expires_utc", request.ExpiresUtc, required: false);
        }
        else
        {
            rule.Remove("score_delta");
            rule.Remove("owner");
            rule.Remove("tag");
            rule.Remove("expires_utc");
        }

        JsonNode? match = ParseJsonNode(String.IsNullOrWhiteSpace(request.MatchJson) ? "{}" : request.MatchJson, "Match JSON");
        if (match is not JsonObject)
        {
            throw new InvalidOperationException("Match JSON must be an object.");
        }

        rule["match"] = match;

        if (request.IsNew || request.RuleIndex < 0 || request.RuleIndex >= rules.Count)
        {
            rules.Add(rule);
        }
        else
        {
            rules[request.RuleIndex] = rule;
        }
    }

    private static void SaveSettingEdit(JsonObject root, ArcanePolicyEditRequest request)
    {
        string sectionName = FirstNonEmpty(request.SectionName, SectionNameForScope(request.Scope));
        if (String.IsNullOrWhiteSpace(sectionName))
        {
            throw new InvalidOperationException("Choose a policy setting scope before saving.");
        }

        string id = request.Id.Trim();
        if (String.IsNullOrWhiteSpace(id))
        {
            throw new InvalidOperationException("Policy setting key is required.");
        }

        JsonObject section = GetObjectSection(root, sectionName, create: true);
        JsonNode? value = ParseJsonNode(request.ValueJson, "Value JSON");
        if (!request.IsNew &&
            !String.IsNullOrWhiteSpace(request.OriginalId) &&
            !request.OriginalId.Equals(id, StringComparison.OrdinalIgnoreCase))
        {
            section.Remove(request.OriginalId);
        }

        if (request.IsNew && section.TryGetPropertyValue(id, out JsonNode? existing))
        {
            section[id] = MergeSettingValue(existing, value);
        }
        else
        {
            section[id] = value;
        }
    }

    private static JsonNode? MergeSettingValue(JsonNode? existing, JsonNode? incoming)
    {
        if (existing is JsonArray existingArray && incoming is JsonArray incomingArray)
        {
            JsonArray merged = new JsonArray();
            foreach (JsonNode? node in existingArray)
            {
                merged.Add(CloneNode(node));
            }

            foreach (JsonNode? node in incomingArray)
            {
                if (!merged.Any(existingNode => JsonNodeEquivalent(existingNode, node)))
                {
                    merged.Add(CloneNode(node));
                }
            }

            return merged;
        }

        if (existing is JsonObject existingObject && incoming is JsonObject incomingObject)
        {
            JsonObject merged = (JsonObject)CloneNode(existingObject)!;
            foreach (KeyValuePair<string, JsonNode?> incomingItem in incomingObject)
            {
                if (merged.TryGetPropertyValue(incomingItem.Key, out JsonNode? existingChild) &&
                    existingChild is JsonArray existingChildArray &&
                    incomingItem.Value is JsonArray incomingChildArray)
                {
                    merged[incomingItem.Key] = MergeSettingValue(existingChildArray, incomingChildArray);
                }
                else
                {
                    merged[incomingItem.Key] = CloneNode(incomingItem.Value);
                }
            }

            return merged;
        }

        return CloneNode(incoming);
    }

    private static bool JsonNodeEquivalent(JsonNode? left, JsonNode? right)
    {
        if (left == null || right == null)
        {
            return left == null && right == null;
        }

        return JsonNodeKey(left).Equals(JsonNodeKey(right), StringComparison.OrdinalIgnoreCase);
    }

    private static string JsonNodeKey(JsonNode node)
    {
        try
        {
            JsonValue value = node.AsValue();
            if (value.TryGetValue(out string? text))
            {
                return text;
            }
        }
        catch
        {
            // Non-scalar nodes compare by their compact JSON form.
        }

        return node.ToJsonString();
    }

    private static JsonObject ExistingRuleObject(JsonArray rules, ArcanePolicyEditRequest request)
    {
        if (!request.IsNew && request.RuleIndex >= 0 && request.RuleIndex < rules.Count && rules[request.RuleIndex] is JsonObject existing)
        {
            return (JsonObject)CloneNode(existing)!;
        }

        return new JsonObject();
    }

    private static JsonObject LoadRootObject()
    {
        string path = ArcanePaths.Discover().PolicyFile;
        if (String.IsNullOrWhiteSpace(path))
        {
            throw new InvalidOperationException("PolicyFile is not configured.");
        }

        string text = File.Exists(path) ? File.ReadAllText(path) : "{}";
        JsonNode? node = JsonNode.Parse(String.IsNullOrWhiteSpace(text) ? "{}" : text);
        if (node is not JsonObject root)
        {
            throw new InvalidOperationException("Policy JSON root must be an object.");
        }

        return root;
    }

    private static string SaveRoot(JsonObject root)
    {
        return ArcanePolicyDocument.SaveFormatted(root.ToJsonString(GuiJson.IndentedOptions));
    }

    private static JsonArray GetRuleArray(JsonObject root, string sectionName, bool create)
    {
        if (root.TryGetPropertyValue(sectionName, out JsonNode? existing) && existing is JsonArray array)
        {
            return array;
        }

        if (!create)
        {
            throw new InvalidOperationException("Policy rule section not found: " + sectionName);
        }

        JsonArray created = new JsonArray();
        root[sectionName] = created;
        return created;
    }

    private static JsonObject GetObjectSection(JsonObject root, string sectionName, bool create)
    {
        if (root.TryGetPropertyValue(sectionName, out JsonNode? existing) && existing is JsonObject section)
        {
            return section;
        }

        if (!create)
        {
            throw new InvalidOperationException("Policy section not found: " + sectionName);
        }

        JsonObject created = new JsonObject();
        root[sectionName] = created;
        return created;
    }

    private static JsonNode? ParseJsonNode(string json, string label)
    {
        try
        {
            return JsonNode.Parse(String.IsNullOrWhiteSpace(json) ? "null" : json);
        }
        catch (Exception ex)
        {
            throw new InvalidOperationException(label + " is not valid JSON: " + ex.Message, ex);
        }
    }

    private static JsonNode? CloneNode(JsonNode? node)
    {
        return node == null ? null : JsonNode.Parse(node.ToJsonString());
    }

    private static void AssignDisplayOrder(ArcanePolicySnapshot snapshot)
    {
        int index = 0;
        foreach (ArcanePolicyEntry entry in snapshot.Entries
            .OrderBy(entry => PolicyScopeCatalog.SortOrder(entry.Scope))
            .ThenBy(entry => entry.SectionIndex)
            .ThenBy(entry => entry.Id))
        {
            index++;
            entry.DisplayOrder = index;
        }
    }

    private static void SetString(JsonObject obj, string name, string value, bool required)
    {
        string text = value == null ? "" : value.Trim();
        if (text.Length == 0 && !required)
        {
            obj.Remove(name);
            return;
        }

        obj[name] = text;
    }

    private static void SetNumber(JsonObject obj, string name, string value, bool removeWhenBlank)
    {
        string text = value == null ? "" : value.Trim();
        if (text.Length == 0)
        {
            if (removeWhenBlank) obj.Remove(name);
            return;
        }

        if (!Int32.TryParse(text, System.Globalization.NumberStyles.Integer, System.Globalization.CultureInfo.InvariantCulture, out int parsed))
        {
            throw new InvalidOperationException(name + " must be a whole number.");
        }

        obj[name] = parsed;
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
        return GuiJson.Format(element);
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
