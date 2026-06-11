namespace ArcaneEDR
{
    internal static class AlertSeverity
    {
        public static string FromScore(int score)
        {
            if (score >= 90) return "critical";
            if (score >= 75) return "high";
            if (score >= 60) return "medium";
            return "low";
        }
    }
}
