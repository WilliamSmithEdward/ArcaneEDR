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

internal sealed class PolicyMatchFieldDefinition
{
    public string Label { get; init; } = "";
    public string NetworkField { get; init; } = "";
    public string DetectionField { get; init; } = "";
    public string InitialValueSource { get; init; } = "";
    public string OptionsSource { get; init; } = "";
    public bool DefaultNetwork { get; init; }
    public bool DefaultDetection { get; init; }
    public string Help { get; init; } = "";
}

internal sealed class PolicySettingChoice
{
    public string Scope { get; init; } = "";
    public string Key { get; init; } = "";
    public string Label { get; init; } = "";
    public string Help { get; init; } = "";
    public string ValueKind { get; init; } = "list";
    public string MapKeyHeader { get; init; } = "Key";
    public string MapKeyPlaceholder { get; init; } = "";
    public string ValuesHeader { get; init; } = "Values";
    public string ValuesPlaceholder { get; init; } = "one value per line";
}

internal static class PolicyScopeCatalog
{
    private static readonly IReadOnlyList<string> FallbackActions = new[] { "observe" };
    public static readonly IReadOnlyList<string> KnownCategories = new[]
    {
        "Agent",
        "AI",
        "Auth",
        "Baseline",
        "File",
        "Health",
        "Network",
        "PowerShell",
        "Registry",
        "Response",
        "Sysmon"
    };

    public static readonly IReadOnlyList<string> KnownCountryCodes = new[]
    {
        "AU",
        "CA",
        "CH",
        "DE",
        "FR",
        "GB",
        "IE",
        "JP",
        "NL",
        "NZ",
        "SE",
        "SG",
        "US"
    };

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

    public static readonly IReadOnlyList<PolicyMatchFieldDefinition> MatchFieldDefinitions = new[]
    {
        new PolicyMatchFieldDefinition
        {
            Label = "ASN",
            NetworkField = "asn",
            InitialValueSource = "metadata:asn",
            Help = "Match the remote ASN."
        },
        new PolicyMatchFieldDefinition
        {
            Label = "ASN org",
            NetworkField = "asn_org",
            InitialValueSource = "metadata:asn_org",
            Help = "Match the enriched ASN organization."
        },
        new PolicyMatchFieldDefinition
        {
            Label = "Category",
            DetectionField = "category",
            InitialValueSource = "category",
            OptionsSource = "categories",
            Help = "Match the alert category."
        },
        new PolicyMatchFieldDefinition
        {
            Label = "Command terms",
            DetectionField = "command_terms",
            InitialValueSource = "metadata:command_line",
            Help = "Match durable command-line terms. Prefer a stable term or phrase rather than the entire command line."
        },
        new PolicyMatchFieldDefinition
        {
            Label = "Company / owner",
            NetworkField = "remote_identity",
            InitialValueSource = "company",
            Help = "Match provider identity text such as owner, ASN org, or ASN."
        },
        new PolicyMatchFieldDefinition
        {
            Label = "Country",
            NetworkField = "country",
            InitialValueSource = "country",
            OptionsSource = "countries",
            Help = "Match the remote country. Use carefully because country-only matches can be broad."
        },
        new PolicyMatchFieldDefinition
        {
            Label = "Country lookup status",
            NetworkField = "country_lookup",
            InitialValueSource = "metadata:country_lookup",
            Help = "Match the enrichment country lookup status, such as unresolved or fallback lookup outcomes."
        },
        new PolicyMatchFieldDefinition
        {
            Label = "Country not in",
            NetworkField = "country_not",
            InitialValueSource = "country",
            OptionsSource = "countries",
            Help = "Match when the remote country is outside this allowed set. This is broad; pair with another field unless intentionally escalating country context."
        },
        new PolicyMatchFieldDefinition
        {
            Label = "DNS name",
            NetworkField = "dns_name",
            InitialValueSource = "metadata:dns_names",
            Help = "Match enriched DNS names associated with the remote endpoint."
        },
        new PolicyMatchFieldDefinition
        {
            Label = "Domain",
            NetworkField = "domain",
            DetectionField = "destination_domain",
            InitialValueSource = "domain",
            Help = "Match destination domain context."
        },
        new PolicyMatchFieldDefinition
        {
            Label = "Hash / SHA256",
            DetectionField = "hash",
            InitialValueSource = "metadata:sha256",
            Help = "Match the process or file hash from the alert."
        },
        new PolicyMatchFieldDefinition
        {
            Label = "Owner",
            NetworkField = "owner",
            InitialValueSource = "metadata:remote_owner",
            Help = "Match the enriched remote owner."
        },
        new PolicyMatchFieldDefinition
        {
            Label = "Parent process",
            DetectionField = "parent_process",
            InitialValueSource = "metadata:parent",
            Help = "Match the parent process from the alert lineage."
        },
        new PolicyMatchFieldDefinition
        {
            Label = "Process name",
            NetworkField = "process_name",
            DetectionField = "process_name",
            InitialValueSource = "process",
            Help = "Match the process name from the alert."
        },
        new PolicyMatchFieldDefinition
        {
            Label = "Process path prefix",
            DetectionField = "path_prefix",
            InitialValueSource = "metadata:process_path",
            Help = "Match the executable path prefix. Edit a full path to the stable parent folder when possible."
        },
        new PolicyMatchFieldDefinition
        {
            Label = "Remote IP / CIDR",
            NetworkField = "remote_ip",
            DetectionField = "ip_cidr",
            InitialValueSource = "remote_ip",
            Help = "Match this exact remote IP, or edit to a CIDR range."
        },
        new PolicyMatchFieldDefinition
        {
            Label = "RDNS name",
            NetworkField = "rdns",
            InitialValueSource = "metadata:rdns",
            Help = "Match reverse-DNS context from remote endpoint enrichment."
        },
        new PolicyMatchFieldDefinition
        {
            Label = "Remote port",
            NetworkField = "port",
            DetectionField = "port",
            InitialValueSource = "metadata:remote_port",
            Help = "Match the remote port. Enter any TCP/UDP port number."
        },
        new PolicyMatchFieldDefinition
        {
            Label = "Resolved domain",
            NetworkField = "resolved_domain",
            InitialValueSource = "metadata:resolved_domain",
            Help = "Match the resolved destination domain."
        },
        new PolicyMatchFieldDefinition
        {
            Label = "Registrable domain",
            NetworkField = "registrable_domain",
            InitialValueSource = "metadata:registrable_domain",
            Help = "Match the normalized registrable domain from enrichment."
        },
        new PolicyMatchFieldDefinition
        {
            Label = "Rule ID",
            DetectionField = "rule_id",
            InitialValueSource = "rule_id",
            Help = "Match the alert rule id."
        },
        new PolicyMatchFieldDefinition
        {
            Label = "Signer",
            DetectionField = "signer",
            InitialValueSource = "metadata:signer",
            Help = "Match the signer subject from the alert. Leave blank for unsigned files."
        },
        new PolicyMatchFieldDefinition
        {
            Label = "SNI hostname",
            NetworkField = "sni_hostname",
            InitialValueSource = "metadata:sni_hostname",
            Help = "Match the TLS SNI hostname."
        },
        new PolicyMatchFieldDefinition
        {
            Label = "Text contains",
            NetworkField = "text_contains",
            DetectionField = "text_contains",
            InitialValueSource = "title",
            Help = "Match policy text. Prefer stronger structured fields when possible."
        },
        new PolicyMatchFieldDefinition
        {
            Label = "User / account",
            DetectionField = "user",
            InitialValueSource = "metadata:user",
            Help = "Match the user or account context from the alert when present."
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

    public static IReadOnlyList<string> OptionsForSource(string source)
    {
        if (source.Equals("categories", StringComparison.OrdinalIgnoreCase))
        {
            return KnownCategories;
        }

        if (source.Equals("countries", StringComparison.OrdinalIgnoreCase))
        {
            return KnownCountryCodes;
        }

        return Array.Empty<string>();
    }

    public static IReadOnlyList<PolicySettingChoice> SettingChoicesForScope(string scope)
    {
        if (scope.Equals("Allowlist", StringComparison.OrdinalIgnoreCase))
        {
            return new[]
            {
                ListChoice(scope, "allowed_dns_resolvers", "Allowed DNS resolvers", "DNS resolver IP addresses that are expected on this workstation.", "DNS resolver IPs"),
                ListChoice(scope, "allowed_listening_ports", "Allowed listening ports", "Inbound/listening local ports expected on this workstation.", "ports or ranges"),
                ListChoice(scope, "allowed_outbound_ports", "Allowed outbound ports", "Outbound remote ports expected on this workstation.", "ports"),
                ListChoice(scope, "allowed_remote_countries", "Allowed remote countries", "Remote country codes that should not escalate on country alone.", "country codes"),
                MapListChoice(scope, "process_allowed_outbound_ports", "Process allowed outbound ports", "Per-process outbound port allowlist. Use this when only one process should be allowed to use a port.", "Process name", "example.exe", "ports"),
                ListChoice(scope, "trusted_persistence_name_prefixes", "Trusted persistence name prefixes", "Startup/task/service name prefixes that are expected local persistence context.", "prefixes"),
                ListChoice(scope, "trusted_persistence_path_indicators", "Trusted persistence path indicators", "Path fragments that indicate expected persistence locations.", "path fragments"),
                ListChoice(scope, "trusted_persistence_signer_subjects", "Trusted persistence signer subjects", "Signer subject text that indicates expected persistence publishers.", "signer subject text"),
                ListChoice(scope, "trusted_processes", "Trusted processes", "Process names commonly expected on this workstation.", "process names")
            };
        }

        if (scope.Equals("Blocklist", StringComparison.OrdinalIgnoreCase))
        {
            return new[]
            {
                ListChoice(scope, "blocked_domains", "Blocked domains", "Domains or domain patterns that should be treated as bad context.", "domains"),
                ListChoice(scope, "blocked_hashes", "Blocked hashes", "SHA-256 hashes that should be treated as bad context.", "SHA-256 hashes")
            };
        }

        if (scope.Equals("Response", StringComparison.OrdinalIgnoreCase))
        {
            return new[]
            {
                ListChoice(scope, "allowed_categories", "Allowed response categories", "Detection categories allowed to perform active response when response mode permits it.", "categories"),
                ListChoice(scope, "allowed_rule_ids", "Allowed response rule IDs", "Rule IDs allowed to perform active response when response mode permits it.", "rule IDs"),
                ListChoice(scope, "blocked_categories", "Blocked response categories", "Detection categories blocked from active response.", "categories"),
                ListChoice(scope, "blocked_rule_ids", "Blocked response rule IDs", "Rule IDs blocked from active response.", "rule IDs"),
                ListChoice(scope, "protected_process_names", "Protected process names", "Processes that active response must not terminate.", "process names")
            };
        }

        return Array.Empty<PolicySettingChoice>();
    }

    public static PolicySettingChoice SelectedSettingChoice(string scope, string key)
    {
        IReadOnlyList<PolicySettingChoice> choices = SettingChoicesForScope(scope);
        return choices.FirstOrDefault(choice => choice.Key.Equals(key, StringComparison.OrdinalIgnoreCase)) ??
            choices.OrderBy(choice => choice.Label, StringComparer.OrdinalIgnoreCase).FirstOrDefault() ??
            ListChoice(scope, "values", "Values", "Policy values.", "values");
    }

    public static string DefaultSettingKeyForScope(string scope, ArcaneAlertRecord? alert)
    {
        if (scope.Equals("Allowlist", StringComparison.OrdinalIgnoreCase))
        {
            if (!String.IsNullOrWhiteSpace(alert?.Country)) return "allowed_remote_countries";
            if (!String.IsNullOrWhiteSpace(alert?.Process)) return "trusted_processes";
            return "allowed_remote_countries";
        }

        if (scope.Equals("Blocklist", StringComparison.OrdinalIgnoreCase))
        {
            if (!String.IsNullOrWhiteSpace(alert?.MetadataValue("sha256"))) return "blocked_hashes";
            return "blocked_domains";
        }

        if (scope.Equals("Response", StringComparison.OrdinalIgnoreCase))
        {
            if (!String.IsNullOrWhiteSpace(alert?.RuleId)) return "blocked_rule_ids";
            return "blocked_categories";
        }

        return "";
    }

    public static string DefaultSettingMapKey(PolicySettingChoice choice, ArcaneAlertRecord? alert)
    {
        if (choice.Key.Equals("process_allowed_outbound_ports", StringComparison.OrdinalIgnoreCase))
        {
            return alert?.Process ?? "";
        }

        return "";
    }

    public static IReadOnlyList<string> DefaultSettingValues(PolicySettingChoice choice, ArcaneAlertRecord? alert)
    {
        string domain = FirstNonEmpty(
            alert?.MetadataValue("registrable_domain"),
            alert?.MetadataValue("resolved_domain"),
            alert?.MetadataValue("sni_hostname"),
            alert?.MetadataValue("rdns"));

        string value = choice.Key switch
        {
            "allowed_dns_resolvers" => alert?.RemoteIp ?? "",
            "allowed_listening_ports" => alert?.MetadataValue("remote_port") ?? "",
            "allowed_outbound_ports" => alert?.MetadataValue("remote_port") ?? "",
            "allowed_remote_countries" => alert?.Country ?? "",
            "process_allowed_outbound_ports" => alert?.MetadataValue("remote_port") ?? "",
            "trusted_processes" => alert?.Process ?? "",
            "blocked_domains" => domain,
            "blocked_hashes" => alert?.MetadataValue("sha256") ?? "",
            "allowed_categories" => alert?.Category ?? "",
            "allowed_rule_ids" => alert?.RuleId ?? "",
            "blocked_categories" => alert?.Category ?? "",
            "blocked_rule_ids" => alert?.RuleId ?? "",
            "protected_process_names" => alert?.Process ?? "",
            _ => ""
        };

        return String.IsNullOrWhiteSpace(value) ? Array.Empty<string>() : new[] { value };
    }

    private static PolicySettingChoice ListChoice(string scope, string key, string label, string help, string valueName)
    {
        return new PolicySettingChoice
        {
            Scope = scope,
            Key = key,
            Label = label,
            Help = help + " Enter one or more " + valueName + ", one per line.",
            ValuesHeader = valueName,
            ValuesPlaceholder = "one " + valueName.TrimEnd('s') + " per line"
        };
    }

    private static PolicySettingChoice MapListChoice(string scope, string key, string label, string help, string mapKeyHeader, string mapKeyPlaceholder, string valueName)
    {
        return new PolicySettingChoice
        {
            Scope = scope,
            Key = key,
            Label = label,
            Help = help + " Enter the map key and one or more " + valueName + ", one per line.",
            ValueKind = "map-list",
            MapKeyHeader = mapKeyHeader,
            MapKeyPlaceholder = mapKeyPlaceholder,
            ValuesHeader = valueName,
            ValuesPlaceholder = "one " + valueName.TrimEnd('s') + " per line"
        };
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

    private static string FirstNonEmpty(params string?[] values)
    {
        foreach (string? value in values)
        {
            if (!String.IsNullOrWhiteSpace(value))
            {
                return value;
            }
        }

        return "";
    }
}
