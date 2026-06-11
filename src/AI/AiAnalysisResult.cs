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
            builder.AppendLine("Provider: " + TextFormatting.EmptyIfNull(ProviderName));
            builder.AppendLine("Alertable: " + Alertable);
            builder.AppendLine("Score: " + Score.ToString(CultureInfo.InvariantCulture));
            builder.AppendLine("Title: " + TextFormatting.EmptyIfNull(Title));
            builder.AppendLine("Summary: " + TextFormatting.EmptyIfNull(Summary));
            builder.AppendLine("RecommendedAction: " + TextFormatting.EmptyIfNull(RecommendedAction));

            if (ProviderOutcomes.Count > 1)
            {
                builder.AppendLine();
                builder.AppendLine("Provider results:");
                foreach (AiProviderAnalysisOutcome outcome in ProviderOutcomes)
                {
                    builder.AppendLine("- " + TextFormatting.EmptyIfNull(outcome.ProviderName) +
                        " status=" + TextFormatting.EmptyIfNull(outcome.Status) +
                        " alertable=" + outcome.Alertable +
                        " score=" + outcome.Score.ToString(CultureInfo.InvariantCulture) +
                        " title=" + TextFormatting.EmptyIfNull(outcome.Title));
                }
            }

            return builder.ToString();
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
