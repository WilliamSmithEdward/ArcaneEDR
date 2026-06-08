using System;

namespace ArcaneEDR
{
    internal static class MaintenanceAlertAnnotator
    {
        public static Alert Annotate(MonitorConfig config, Alert alert)
        {
            if (alert == null || config == null || !config.EnableMaintenanceContext)
            {
                return alert;
            }

            if (alert.MaintenanceContext)
            {
                return alert;
            }

            MaintenanceSessionMarker marker = new MaintenanceSessionMarkerStore(config, null).FindActive(alert.TimestampUtc);
            if (marker != null)
            {
                string markerSummary = marker.AnnotationSummary(alert.TimestampUtc);
                alert.MaintenanceContext = true;
                alert.Body = AppendLine(alert.Body, "MaintenanceContext: involved=true " + markerSummary);
                alert.EntitySummary = AppendEntity(alert.EntitySummary, "maintenance_context=involved " + markerSummary);
                alert.AddWhy("The alert occurred during an active maintenance session marker: " + markerSummary + ".");
                return alert;
            }

            string matchedGroup = TermGroupRules.FindFirstMatchingGroup(AlertText(alert), config.MaintenanceContextTermGroups);
            if (String.IsNullOrWhiteSpace(matchedGroup)) return alert;

            string summary = NormalizeReason(matchedGroup);
            alert.MaintenanceContext = true;
            alert.Body = AppendLine(alert.Body, "MaintenanceContext: involved=true matched_group=" + summary);
            alert.EntitySummary = AppendEntity(alert.EntitySummary, "maintenance_context=involved matched_group=" + summary);
            alert.AddWhy("The alert matched configured maintenance context: " + summary + ".");
            return alert;
        }

        private static string AlertText(Alert alert)
        {
            return (alert.RuleId ?? "") + " " +
                (alert.Title ?? "") + " " +
                (alert.Body ?? "") + " " +
                (alert.EntitySummary ?? "");
        }

        private static string AppendLine(string value, string line)
        {
            if (String.IsNullOrWhiteSpace(value)) return line;
            return value + Environment.NewLine + line;
        }

        private static string AppendEntity(string value, string addition)
        {
            if (String.IsNullOrWhiteSpace(value)) return addition;
            return value + " " + addition;
        }

        private static string NormalizeReason(string value)
        {
            if (String.IsNullOrWhiteSpace(value)) return "";

            string normalized = value.Trim()
                .Replace("\\", "/")
                .Replace(" ", "_")
                .Replace(",", "_")
                .Replace(";", "_")
                .Replace("|", "+")
                .Replace("\r", "")
                .Replace("\n", "");

            if (normalized.Length <= 120) return normalized;
            return normalized.Substring(0, 120);
        }
    }
}
