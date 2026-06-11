using System;

namespace ArcaneEDR
{
    internal static class AlertWhyText
    {
        public static string Join(Alert alert, string separator)
        {
            if (alert == null || alert.Why == null || alert.Why.Count == 0) return "";
            return String.Join(separator ?? "; ", alert.Why.ToArray());
        }

        public static string JoinWithPrefix(Alert alert, string prefix, string separator, string suffix)
        {
            string why = Join(alert, separator);
            return String.IsNullOrWhiteSpace(why) ? "" : (prefix ?? "") + why + (suffix ?? "");
        }
    }
}
