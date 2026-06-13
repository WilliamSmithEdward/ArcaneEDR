namespace ArcaneEDR
{
    internal static class AlertScore
    {
        public static int Clamp(int score)
        {
            if (score < 0) return 0;
            if (score > 100) return 100;
            return score;
        }
    }
}
