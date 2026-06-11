using System;
using System.Collections.Generic;

namespace ArcaneEDR
{
    internal static class AgentAlertAnnotator
    {
        public static Alert Annotate(MonitorConfig config, Alert alert)
        {
            if (alert == null || config == null || !config.EnableAgentProfile)
            {
                return alert;
            }

            string text = AlertText.Build(alert);
            if (text.IndexOf("agent_context=", StringComparison.OrdinalIgnoreCase) >= 0)
            {
                return alert;
            }

            List<string> reasons = new List<string>();
            AddProcessMatches(reasons, text, "agent-process", config.AgentProcessNames);
            AddParentMatches(reasons, text, config.AgentProcessNames);
            AddProcessMatches(reasons, text, "agent-child-process", config.AgentChildProcessNames);
            AddContainsMatches(reasons, text, "agent-workspace", config.AgentWorkspaceRoots);
            AddContainsMatches(reasons, text, "agent-publish-root", config.AgentPublishRoots);
            AddProcessMatches(reasons, text, "agent-package-tool", config.AgentPackageManagerProcesses);
            AddContainsMatches(reasons, text, "approved-admin-task", config.AgentApprovedAdminTaskNames);
            AddContainsMatches(reasons, text, "secret-indicator", config.AgentSecretIndicatorTerms);

            if (reasons.Count == 0)
            {
                return alert;
            }

            string summary = String.Join(",", reasons.ToArray());
            alert.Body = AlertAnnotationText.AppendLine(alert.Body, "AgentContext: involved=true reasons=" + summary);
            alert.EntitySummary = AlertAnnotationText.AppendEntity(alert.EntitySummary, "agent_context=involved reasons=" + summary);
            alert.AddWhy("The alert involves configured unattended-agent context: " + summary + ".");
            return alert;
        }

        private static void AddProcessMatches(List<string> reasons, string text, string label, HashSet<string> processNames)
        {
            foreach (string processName in processNames)
            {
                if (String.IsNullOrWhiteSpace(processName)) continue;
                if (ContainsProcessField(text, "process=", processName) ||
                    ContainsProcessField(text, "process_name=", processName))
                {
                    AddUnique(reasons, label + ":" + NormalizeReason(processName));
                }
            }
        }

        private static void AddParentMatches(List<string> reasons, string text, HashSet<string> processNames)
        {
            foreach (string processName in processNames)
            {
                if (String.IsNullOrWhiteSpace(processName)) continue;
                if (ContainsProcessField(text, "parent=", processName) ||
                    ContainsProcessField(text, "parent_process=", processName) ||
                    ContainsProcessField(text, "parent_process_name=", processName))
                {
                    AddUnique(reasons, "agent-parent:" + NormalizeReason(processName));
                }
            }
        }

        private static void AddContainsMatches(List<string> reasons, string text, string label, HashSet<string> terms)
        {
            bool rootMatch = label.Equals("agent-workspace", StringComparison.OrdinalIgnoreCase) ||
                label.Equals("agent-publish-root", StringComparison.OrdinalIgnoreCase);

            foreach (string term in terms)
            {
                if (String.IsNullOrWhiteSpace(term)) continue;
                bool matched = rootMatch
                    ? ContainsRootText(text, term)
                    : text.IndexOf(term, StringComparison.OrdinalIgnoreCase) >= 0;
                if (matched)
                {
                    AddUnique(reasons, label + ":" + NormalizeReason(term));
                }
            }
        }

        private static bool ContainsProcessField(string text, string fieldName, string processName)
        {
            int index = text.IndexOf(fieldName, StringComparison.OrdinalIgnoreCase);
            while (index >= 0)
            {
                int start = index + fieldName.Length;
                if (ValueMatchesAt(text, start, processName)) return true;
                index = text.IndexOf(fieldName, index + fieldName.Length, StringComparison.OrdinalIgnoreCase);
            }

            return false;
        }

        private static bool ValueMatchesAt(string text, int start, string expected)
        {
            int index = start;
            while (index < text.Length && Char.IsWhiteSpace(text[index]))
            {
                index++;
            }

            if (index < text.Length && text[index] == '"')
            {
                index++;
            }

            if (index + expected.Length > text.Length) return false;
            if (!text.Substring(index, expected.Length).Equals(expected, StringComparison.OrdinalIgnoreCase))
            {
                return false;
            }

            int after = index + expected.Length;
            return after >= text.Length || TextFormatting.IsTokenBoundary(text[after]);
        }

        private static void AddUnique(List<string> reasons, string value)
        {
            foreach (string existing in reasons)
            {
                if (existing.Equals(value, StringComparison.OrdinalIgnoreCase)) return;
            }

            reasons.Add(value);
        }

        private static string NormalizeReason(string value)
        {
            return AlertAnnotationText.NormalizeReasonToken(value, 80, "_");
        }

        private static bool ContainsRootText(string text, string root)
        {
            string normalizedText = NormalizePathText(text);
            string normalizedRoot = NormalizeRoot(root);
            return !String.IsNullOrWhiteSpace(normalizedText) &&
                !String.IsNullOrWhiteSpace(normalizedRoot) &&
                normalizedText.IndexOf(normalizedRoot, StringComparison.OrdinalIgnoreCase) >= 0;
        }

        private static string NormalizeRoot(string root)
        {
            if (String.IsNullOrWhiteSpace(root)) return "";
            return NormalizePathText(root).TrimEnd('\\') + "\\";
        }

        private static string NormalizePathText(string value)
        {
            return value == null ? "" : value.Replace('/', '\\');
        }
    }
}
