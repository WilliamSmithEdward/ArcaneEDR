namespace ArcaneEDR
{
    internal sealed class OpenAiAnalysisResult
    {
        public bool Alertable;
        public int Score;
        public string Title;
        public string Summary;
        public string RecommendedAction;
        public string RawText;

        public string ToBody()
        {
            return "OpenAI compact log analysis" + System.Environment.NewLine +
                "Alertable: " + Alertable + System.Environment.NewLine +
                "Score: " + Score + System.Environment.NewLine +
                "Title: " + Safe(Title) + System.Environment.NewLine +
                "Summary: " + Safe(Summary) + System.Environment.NewLine +
                "RecommendedAction: " + Safe(RecommendedAction);
        }

        private static string Safe(string value)
        {
            return value == null ? "" : value;
        }
    }
}
