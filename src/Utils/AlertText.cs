namespace ArcaneEDR
{
    internal static class AlertText
    {
        public static string Build(Alert alert)
        {
            if (alert == null) return "";

            return (alert.RuleId ?? "") + " " +
                (alert.Title ?? "") + " " +
                (alert.Body ?? "") + " " +
                (alert.EntitySummary ?? "");
        }

        public static string BuildForPolicy(Alert alert)
        {
            if (alert == null) return "";

            return (alert.RuleId ?? "") + " " +
                (alert.Category ?? "") + " " +
                (alert.Title ?? "") + " " +
                (alert.Body ?? "") + " " +
                (alert.EntitySummary ?? "") + " " +
                (alert.PolicyContext ?? "");
        }
    }
}
