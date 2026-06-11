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
                alert.Body = AlertAnnotationText.AppendLine(alert.Body, "MaintenanceContext: involved=true " + markerSummary);
                alert.EntitySummary = AlertAnnotationText.AppendEntity(alert.EntitySummary, "maintenance_context=involved " + markerSummary);
                alert.AddWhy("The alert occurred during an active maintenance session marker: " + markerSummary + ".");
                return alert;
            }

            string matchedGroup = TermGroupRules.FindFirstMatchingGroup(AlertText.Build(alert), config.MaintenanceContextTermGroups);
            if (String.IsNullOrWhiteSpace(matchedGroup)) return alert;

            string summary = NormalizeReason(matchedGroup);
            alert.MaintenanceContext = true;
            alert.Body = AlertAnnotationText.AppendLine(alert.Body, "MaintenanceContext: involved=true matched_group=" + summary);
            alert.EntitySummary = AlertAnnotationText.AppendEntity(alert.EntitySummary, "maintenance_context=involved matched_group=" + summary);
            alert.AddWhy("The alert matched configured maintenance context: " + summary + ".");
            return alert;
        }

        private static string NormalizeReason(string value)
        {
            return AlertAnnotationText.NormalizeReasonToken(value, 120, "+");
        }
    }
}
