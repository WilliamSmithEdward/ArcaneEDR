using System;
using System.Collections.Generic;
using System.Globalization;
using System.Text;
using System.Threading.Tasks;

namespace ArcaneEDR
{
    internal sealed class CompositeAiAnalysisProvider : IAiAnalysisProvider
    {
        private readonly List<IAiAnalysisProvider> providers;
        private readonly FileLogger logger;

        public CompositeAiAnalysisProvider(IEnumerable<IAiAnalysisProvider> providers, FileLogger logger)
        {
            this.providers = new List<IAiAnalysisProvider>(providers);
            this.logger = logger;
        }

        public string ProviderName
        {
            get
            {
                List<string> names = new List<string>();
                foreach (IAiAnalysisProvider provider in providers)
                {
                    names.Add(provider.ProviderName);
                }

                return String.Join(",", names.ToArray());
            }
        }

        public bool IsConfigured
        {
            get
            {
                foreach (IAiAnalysisProvider provider in providers)
                {
                    if (provider.IsConfigured) return true;
                }

                return false;
            }
        }

        public string MissingConfigurationReason
        {
            get
            {
                List<string> reasons = new List<string>();
                foreach (IAiAnalysisProvider provider in providers)
                {
                    if (!provider.IsConfigured)
                    {
                        reasons.Add(provider.ProviderName + ": " + provider.MissingConfigurationReason);
                    }
                }

                return reasons.Count == 0 ? "" : String.Join("; ", reasons.ToArray());
            }
        }

        public AiAnalysisResult Analyze(string compactLogPayload)
        {
            return AnalyzeAll(compactLogPayload, false);
        }

        public AiAnalysisResult AnalyzeDailyReport(string dailyReportPayload)
        {
            return AnalyzeAll(dailyReportPayload, true);
        }

        private AiAnalysisResult AnalyzeAll(string payload, bool dailyReport)
        {
            List<Task<ProviderRunResult>> tasks = new List<Task<ProviderRunResult>>();
            foreach (IAiAnalysisProvider provider in providers)
            {
                if (!provider.IsConfigured)
                {
                    logger.Warn("AI analysis provider skipped: " + provider.ProviderName + " reason=" + provider.MissingConfigurationReason);
                    continue;
                }

                IAiAnalysisProvider captured = provider;
                tasks.Add(Task.Factory.StartNew(delegate
                {
                    return RunProvider(captured, payload, dailyReport);
                }));
            }

            if (tasks.Count == 0)
            {
                throw new InvalidOperationException("No configured AI analysis providers are available.");
            }

            Task.WaitAll(tasks.ToArray());

            List<AiProviderAnalysisOutcome> outcomes = new List<AiProviderAnalysisOutcome>();
            List<string> failures = new List<string>();
            AiAnalysisResult strongest = null;

            foreach (Task<ProviderRunResult> task in tasks)
            {
                ProviderRunResult run = task.Result;
                outcomes.Add(run.Outcome);
                if (run.Result == null)
                {
                    failures.Add(run.Outcome.ProviderName + ": " + run.Outcome.Error);
                    continue;
                }

                if (strongest == null ||
                    (run.Result.Alertable && !strongest.Alertable) ||
                    (run.Result.Alertable == strongest.Alertable && run.Result.Score > strongest.Score))
                {
                    strongest = run.Result;
                }
            }

            if (strongest == null)
            {
                throw new InvalidOperationException("All AI analysis providers failed: " + String.Join("; ", failures.ToArray()));
            }

            AiAnalysisResult aggregate = new AiAnalysisResult();
            aggregate.ProviderName = ProviderName;
            aggregate.Alertable = false;
            aggregate.Score = strongest.Score;
            aggregate.Title = strongest.Title;
            aggregate.Summary = BuildAggregateSummary(outcomes, strongest);
            aggregate.RecommendedAction = strongest.RecommendedAction;

            foreach (AiProviderAnalysisOutcome outcome in outcomes)
            {
                aggregate.ProviderOutcomes.Add(outcome);
                if (outcome.Status.Equals("completed", StringComparison.OrdinalIgnoreCase) && outcome.Alertable)
                {
                    aggregate.Alertable = true;
                }
            }

            return aggregate;
        }

        private ProviderRunResult RunProvider(IAiAnalysisProvider provider, string payload, bool dailyReport)
        {
            try
            {
                AiAnalysisResult result = dailyReport
                    ? provider.AnalyzeDailyReport(payload)
                    : provider.Analyze(payload);

                AiProviderAnalysisOutcome outcome = ResultOutcome(provider.ProviderName, result, "completed", "");
                return new ProviderRunResult(result, outcome);
            }
            catch (Exception ex)
            {
                AiProviderAnalysisOutcome outcome = new AiProviderAnalysisOutcome();
                outcome.ProviderName = provider.ProviderName;
                outcome.Status = "failed";
                outcome.Alertable = false;
                outcome.Score = 0;
                outcome.Title = "Provider failed";
                outcome.Summary = "";
                outcome.RecommendedAction = "";
                outcome.Error = ex.Message;
                return new ProviderRunResult(null, outcome);
            }
        }

        private static AiProviderAnalysisOutcome ResultOutcome(string providerName, AiAnalysisResult result, string status, string error)
        {
            AiProviderAnalysisOutcome outcome = new AiProviderAnalysisOutcome();
            outcome.ProviderName = providerName;
            outcome.Status = status;
            outcome.Alertable = result.Alertable;
            outcome.Score = result.Score;
            outcome.Title = result.Title;
            outcome.Summary = result.Summary;
            outcome.RecommendedAction = result.RecommendedAction;
            outcome.Error = error;
            return outcome;
        }

        private static string BuildAggregateSummary(List<AiProviderAnalysisOutcome> outcomes, AiAnalysisResult strongest)
        {
            StringBuilder builder = new StringBuilder();
            builder.Append(Safe(strongest.Summary));
            builder.Append(" Provider consensus: ");

            List<string> parts = new List<string>();
            foreach (AiProviderAnalysisOutcome outcome in outcomes)
            {
                if (outcome.Status.Equals("completed", StringComparison.OrdinalIgnoreCase))
                {
                    parts.Add(Safe(outcome.ProviderName) +
                        " score " + outcome.Score.ToString(CultureInfo.InvariantCulture) +
                        (outcome.Alertable ? " flagged" : " not flagged"));
                }
                else
                {
                    parts.Add(Safe(outcome.ProviderName) + " failed");
                }
            }

            builder.Append(String.Join("; ", parts.ToArray()));
            return builder.ToString();
        }

        private static string Safe(string value)
        {
            return value == null ? "" : value;
        }
    }

    internal sealed class ProviderRunResult
    {
        public readonly AiAnalysisResult Result;
        public readonly AiProviderAnalysisOutcome Outcome;

        public ProviderRunResult(AiAnalysisResult result, AiProviderAnalysisOutcome outcome)
        {
            Result = result;
            Outcome = outcome;
        }
    }
}
