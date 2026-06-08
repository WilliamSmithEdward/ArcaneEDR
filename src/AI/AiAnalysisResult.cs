using System.Collections.Generic;
using System.Globalization;
using System.Text;

namespace ArcaneEDR
{
    internal sealed class AiAnalysisResult
    {
        public string ProviderName;
        public bool Alertable;
        public int Score;
        public string Title;
        public string Summary;
        public string RecommendedAction;
        public string RawText;
        public readonly List<AiProviderAnalysisOutcome> ProviderOutcomes = new List<AiProviderAnalysisOutcome>();

        public string ToBody()
        {
            StringBuilder builder = new StringBuilder();
            builder.AppendLine("AI compact log analysis");
            builder.AppendLine("Provider: " + Safe(ProviderName));
            builder.AppendLine("Alertable: " + Alertable);
            builder.AppendLine("Score: " + Score.ToString(CultureInfo.InvariantCulture));
            builder.AppendLine("Title: " + Safe(Title));
            builder.AppendLine("Summary: " + Safe(Summary));
            builder.AppendLine("RecommendedAction: " + Safe(RecommendedAction));

            if (ProviderOutcomes.Count > 1)
            {
                builder.AppendLine();
                builder.AppendLine("Provider results:");
                foreach (AiProviderAnalysisOutcome outcome in ProviderOutcomes)
                {
                    builder.AppendLine("- " + Safe(outcome.ProviderName) +
                        " status=" + Safe(outcome.Status) +
                        " alertable=" + outcome.Alertable +
                        " score=" + outcome.Score.ToString(CultureInfo.InvariantCulture) +
                        " title=" + Safe(outcome.Title));
                }
            }

            return builder.ToString();
        }

        private static string Safe(string value)
        {
            return value == null ? "" : value;
        }
    }

    internal sealed class AiProviderAnalysisOutcome
    {
        public string ProviderName;
        public string Status;
        public bool Alertable;
        public int Score;
        public string Title;
        public string Summary;
        public string RecommendedAction;
        public string Error;
    }
}
