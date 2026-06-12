using System;
using System.Collections.Generic;
using System.Linq;

namespace ArcaneEDR_Gui.Services;

internal sealed class PolicyScopeDefinition
{
    public string Scope { get; init; } = "";
    public string DisplayName { get; init; } = "";
    public string SectionName { get; init; } = "";
    public bool IsRule { get; init; }
    public string DefaultAction { get; init; } = "";
    public IReadOnlyList<string> Actions { get; init; } = Array.Empty<string>();
    public string DefaultMatchJson { get; init; } = "{}";
    public string DefaultValueJson { get; init; } = "[]";
}

internal static class PolicyScopeCatalog
{
    private static readonly IReadOnlyList<string> FallbackActions = new[] { "observe" };

    private static readonly IReadOnlyList<PolicyScopeDefinition> Definitions = new[]
    {
        new PolicyScopeDefinition
        {
            Scope = "Allowlist",
            DisplayName = "Allowlist",
            SectionName = "allowlists",
            DefaultAction = "allow",
            Actions = new[] { "allow" }
        },
        new PolicyScopeDefinition
        {
            Scope = "Blocklist",
            DisplayName = "Blocklist",
            SectionName = "blocklists",
            DefaultAction = "block",
            Actions = new[] { "block" }
        },
        new PolicyScopeDefinition
        {
            Scope = "Response",
            DisplayName = "Response guardrail",
            SectionName = "response_policy",
            DefaultAction = "allow",
            Actions = new[] { "allow", "block", "protect" }
        },
        new PolicyScopeDefinition
        {
            Scope = "Remote endpoint",
            DisplayName = "Network endpoint",
            SectionName = "remote_endpoint_policies",
            IsRule = true,
            DefaultAction = "observe",
            Actions = new[] { "observe", "allow", "trust", "critical", "block" },
            DefaultMatchJson = "{\n  \"process_name\": \"example.exe\",\n  \"country\": \"US\"\n}"
        },
        new PolicyScopeDefinition
        {
            Scope = "Detection",
            DisplayName = "Alert tuning",
            SectionName = "detection_policies",
            IsRule = true,
            DefaultAction = "suppress_external",
            Actions = new[] { "suppress_external", "lower_score", "raise_score", "force_alert", "tag_only", "trusted_context" },
            DefaultMatchJson = "{\n  \"rule_id\": \"NET-BEACON-TIMING-LOW-RISK\",\n  \"process_name\": \"example.exe\"\n}"
        }
    };

    public static IReadOnlyList<PolicyScopeDefinition> All => Definitions;

    public static IEnumerable<PolicyScopeDefinition> AllAlphabetical()
    {
        return Definitions.OrderBy(definition => definition.DisplayName, StringComparer.OrdinalIgnoreCase);
    }

    private static PolicyScopeDefinition? FindScope(string scope)
    {
        return Definitions.FirstOrDefault(definition =>
            definition.Scope.Equals(scope, StringComparison.OrdinalIgnoreCase));
    }

    public static string DisplayNameForScope(string scope)
    {
        return FindScope(scope)?.DisplayName ?? scope;
    }

    public static string SectionNameForScope(string scope)
    {
        return FindScope(scope)?.SectionName ?? "";
    }

    public static bool IsRuleScope(string scope)
    {
        return FindScope(scope)?.IsRule ?? false;
    }

    public static string DefaultActionForScope(string scope)
    {
        return FindScope(scope)?.DefaultAction ?? "observe";
    }

    public static IReadOnlyList<string> ActionsForScope(string scope)
    {
        return (FindScope(scope)?.Actions ?? FallbackActions)
            .OrderBy(action => action, StringComparer.OrdinalIgnoreCase)
            .ToList();
    }

    public static string ScopeHelpText(string scope)
    {
        if (scope.Equals("Allowlist", StringComparison.OrdinalIgnoreCase))
        {
            return "Known-good lists used by policy, such as trusted countries or resolvers. These reduce unnecessary noise but do not hide unrelated suspicious evidence.";
        }

        if (scope.Equals("Blocklist", StringComparison.OrdinalIgnoreCase))
        {
            return "High-confidence bad or unwanted values. Keep these narrow because matching blocklist context can strongly escalate review.";
        }

        if (scope.Equals("Response", StringComparison.OrdinalIgnoreCase))
        {
            return "Guardrails for active response behavior, protected processes, allowed rules, and blocked response categories.";
        }

        if (scope.Equals("Remote endpoint", StringComparison.OrdinalIgnoreCase))
        {
            return "Network endpoint rules for remote IP, domain, country, provider, ASN, and process context. Use these to trust expected providers or escalate risky destinations.";
        }

        if (scope.Equals("Detection", StringComparison.OrdinalIgnoreCase))
        {
            return "Alert tuning rules applied after a detection fires. They can adjust score, notification behavior, or review language while preserving local evidence.";
        }

        return "Policy entries in this type share the same matching and action model.";
    }

    public static string DefaultMatchJsonForScope(string scope)
    {
        return FindScope(scope)?.DefaultMatchJson ?? "{}";
    }

    public static string DefaultValueJsonForScope(string scope)
    {
        return FindScope(scope)?.DefaultValueJson ?? "[]";
    }

    public static int SortOrder(string scope)
    {
        for (int index = 0; index < Definitions.Count; index++)
        {
            if (Definitions[index].Scope.Equals(scope, StringComparison.OrdinalIgnoreCase))
            {
                return index;
            }
        }

        return Definitions.Count;
    }

    public static bool IsScoreRelevant(string scope, string action)
    {
        if (scope.Equals("Remote endpoint", StringComparison.OrdinalIgnoreCase))
        {
            return action.Equals("observe", StringComparison.OrdinalIgnoreCase) ||
                action.Equals("critical", StringComparison.OrdinalIgnoreCase) ||
                action.Equals("block", StringComparison.OrdinalIgnoreCase);
        }

        if (scope.Equals("Detection", StringComparison.OrdinalIgnoreCase))
        {
            return action.Equals("raise_score", StringComparison.OrdinalIgnoreCase) ||
                action.Equals("lower_score", StringComparison.OrdinalIgnoreCase);
        }

        return false;
    }

    public static bool IsDeltaRelevant(string scope, string action)
    {
        return scope.Equals("Detection", StringComparison.OrdinalIgnoreCase) &&
            (action.Equals("raise_score", StringComparison.OrdinalIgnoreCase) ||
             action.Equals("lower_score", StringComparison.OrdinalIgnoreCase));
    }

    public static string DefaultScoreForAction(string scope, string action)
    {
        if (scope.Equals("Remote endpoint", StringComparison.OrdinalIgnoreCase) &&
            action.Equals("critical", StringComparison.OrdinalIgnoreCase))
        {
            return "90";
        }

        if (scope.Equals("Remote endpoint", StringComparison.OrdinalIgnoreCase) &&
            action.Equals("block", StringComparison.OrdinalIgnoreCase))
        {
            return "95";
        }

        return "";
    }

    public static string DefaultDeltaForAction(string scope, string action)
    {
        return IsDeltaRelevant(scope, action) ? "10" : "";
    }

    public static string ScoreHintText(string scope, string action)
    {
        if (scope.Equals("Remote endpoint", StringComparison.OrdinalIgnoreCase))
        {
            if (action.Equals("allow", StringComparison.OrdinalIgnoreCase))
            {
                return "Score and delta are not used for allow; matching traffic is treated as allowed network context.";
            }

            if (action.Equals("trust", StringComparison.OrdinalIgnoreCase))
            {
                return "Score and delta are not used for trust; matching clean network-shape noise is reduced, but stronger suspicious evidence can still alert.";
            }

            if (action.Equals("critical", StringComparison.OrdinalIgnoreCase) ||
                action.Equals("block", StringComparison.OrdinalIgnoreCase) ||
                action.Equals("observe", StringComparison.OrdinalIgnoreCase))
            {
                return "Score is optional for this network endpoint action. Delta is not used.";
            }
        }

        if (scope.Equals("Detection", StringComparison.OrdinalIgnoreCase))
        {
            if (IsDeltaRelevant(scope, action))
            {
                return "Use Score to set an absolute score, or Delta to adjust the existing score. If both are blank, Arcane uses a default adjustment.";
            }

            return "Score and delta are not used for this alert tuning action.";
        }

        return "Score and delta are not used by this policy type.";
    }

    public static string ActionHelpText(string scope, string action)
    {
        if (scope.Equals("Remote endpoint", StringComparison.OrdinalIgnoreCase))
        {
            if (action.Equals("allow", StringComparison.OrdinalIgnoreCase)) return "Allow matching remote endpoint context. Use narrow matches.";
            if (action.Equals("trust", StringComparison.OrdinalIgnoreCase)) return "Treat matching known-good provider/network context as low-noise, without hiding stronger suspicious evidence.";
            if (action.Equals("observe", StringComparison.OrdinalIgnoreCase)) return "Add review weight for matching endpoint context without immediately treating it as critical.";
            if (action.Equals("critical", StringComparison.OrdinalIgnoreCase)) return "Treat matching endpoint context as critical review material.";
            if (action.Equals("block", StringComparison.OrdinalIgnoreCase)) return "Treat matching endpoint context as high-confidence blocked context. Active blocking still requires response gates.";
        }

        if (scope.Equals("Detection", StringComparison.OrdinalIgnoreCase))
        {
            if (action.Equals("suppress_external", StringComparison.OrdinalIgnoreCase)) return "Keep local evidence, but do not send external notification for matching alerts.";
            if (action.Equals("raise_score", StringComparison.OrdinalIgnoreCase)) return "Increase matching alert score, or set an absolute score.";
            if (action.Equals("lower_score", StringComparison.OrdinalIgnoreCase)) return "Reduce matching alert score, or set an absolute score.";
            if (action.Equals("force_alert", StringComparison.OrdinalIgnoreCase)) return "Force external notification for matching alerts even when ordinary thresholds would skip them.";
            if (action.Equals("tag_only", StringComparison.OrdinalIgnoreCase)) return "Add policy context without changing score or notification behavior.";
            if (action.Equals("trusted_context", StringComparison.OrdinalIgnoreCase)) return "Mark matching alert context as expected/trusted for review language.";
        }

        return "Choose what Arcane should do when this policy matches.";
    }

    public static string ScoreToolTipText(string scope, string action)
    {
        if (!IsScoreRelevant(scope, action))
        {
            return "Not used by the selected action.";
        }

        if (scope.Equals("Remote endpoint", StringComparison.OrdinalIgnoreCase))
        {
            return "Optional absolute 0-100 score for this network endpoint match.";
        }

        return "Optional absolute 0-100 score for matching alerts. Leave blank to use Delta for raise/lower actions.";
    }

    public static string DeltaToolTipText(string scope, string action)
    {
        if (!IsDeltaRelevant(scope, action))
        {
            return "Not used by the selected action.";
        }

        return "Amount to raise or lower the existing alert score when Score is blank.";
    }
}
