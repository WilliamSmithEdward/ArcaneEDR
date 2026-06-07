using System;
using System.Collections;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Text;
using System.Text.RegularExpressions;
using System.Web.Script.Serialization;

namespace ArcaneEDR
{
    internal sealed class DailyReportBuilder
    {
        private readonly MonitorConfig config;
        private readonly HealthState state;
        private readonly string runId;
        private readonly DateTime startedUtc;
        private readonly long currentRunPolls;
        private readonly long currentRunAlerts;
        private readonly long currentRunPollFailures;

        public DailyReportBuilder(
            MonitorConfig config,
            HealthState state,
            string runId,
            DateTime startedUtc,
            long currentRunPolls,
            long currentRunAlerts,
            long currentRunPollFailures)
        {
            this.config = config;
            this.state = state;
            this.runId = runId;
            this.startedUtc = startedUtc;
            this.currentRunPolls = currentRunPolls;
            this.currentRunAlerts = currentRunAlerts;
            this.currentRunPollFailures = currentRunPollFailures;
        }

        public DailyReportSnapshot BuildSnapshot(DateTime nowUtc)
        {
            DailyReportSnapshot snapshot = new DailyReportSnapshot();
            snapshot.GeneratedUtc = nowUtc;
            snapshot.WindowStartUtc = nowUtc.AddHours(-24);
            snapshot.RunId = runId;
            snapshot.CurrentRunUptimeHours = (nowUtc - startedUtc).TotalHours;
            snapshot.CurrentRunPolls = currentRunPolls;
            snapshot.CurrentRunAlerts = currentRunAlerts;
            snapshot.CurrentRunPollFailures = currentRunPollFailures;
            snapshot.TotalPolls = state.PollCount;
            snapshot.TotalAlerts = state.AlertCount;
            snapshot.TotalPollFailures = state.PollFailures;
            snapshot.ExternalSendFailures = state.ExternalSendFailures;
            snapshot.LastCleanStopUtc = state.LastCleanStopUtc;
            snapshot.BaselineLearningMode = config.BaselineLearningMode;
            snapshot.ScheduledLocalTime = DailySummarySchedule.Describe(config);
            snapshot.Alerts.AddRange(LoadAlerts(snapshot.WindowStartUtc));
            snapshot.AgentActivities.AddRange(LoadAgentActivities(snapshot.WindowStartUtc));
            snapshot.Assessment = Assess(snapshot);
            return snapshot;
        }

        public string BuildOpenAiPayload(DailyReportSnapshot snapshot)
        {
            StringBuilder builder = new StringBuilder();
            DailyReportMetrics metrics = CalculateMetrics(snapshot);
            builder.AppendLine("arcane_edr_daily_report_payload");
            builder.AppendLine("privacy_mode=redacted_aggregate_summary_only");
            builder.AppendLine("omitted_fields=alert_body,entity,command_line,script_block,user,path,ip,url,email,secrets");
            builder.AppendLine("analysis_guardrails=do_not_treat_alert_volume_alone_as_compromise;weigh_baseline_learning_maintenance_automation_context_and_telemetry_gaps;state_uncertainty_when_source_context_is_missing");
            builder.AppendLine("recipient_question=is_compromise_confirmed_or_review_required");
            builder.AppendLine("report_verdict=" + SanitizeToken(BuildOperatorVerdict(snapshot, metrics)));
            builder.AppendLine("compromise_assessment=" + SanitizeText(BuildCompromiseAssessment(snapshot, metrics)));
            builder.AppendLine("confidence=" + SanitizeToken(BuildConfidence(snapshot)));
            builder.AppendLine("analyzed_window_system_time=" + SanitizeText(FormatSystemLocalTime(snapshot.WindowStartUtc) + " to " + FormatSystemLocalTime(snapshot.GeneratedUtc)));
            builder.AppendLine("generated_system_time=" + SanitizeText(FormatSystemLocalTime(snapshot.GeneratedUtc)));
            builder.AppendLine("analyzed_window_utc=" + Format(snapshot.WindowStartUtc) + " to " + Format(snapshot.GeneratedUtc));
            AppendCoreReport(builder, snapshot, false, metrics);
            return Limit(builder.ToString(), config.OpenAIAnalysisMaxChars);
        }

        public string BuildReport(DailyReportSnapshot snapshot, OpenAiAnalysisResult aiResult, string aiStatus)
        {
            StringBuilder builder = new StringBuilder();
            DailyReportMetrics metrics = CalculateMetrics(snapshot);
            AppendQuickVerdict(builder, snapshot, metrics);
            builder.AppendLine();

            builder.AppendLine("## Critical Callouts");
            AppendCriticalCallouts(builder, snapshot, metrics);
            builder.AppendLine();

            AppendCoreReport(builder, snapshot, true, metrics);
            builder.AppendLine();
            builder.AppendLine("## OpenAI Review");
            builder.AppendLine("| Field | Value |");
            builder.AppendLine("| --- | --- |");
            builder.AppendLine("| Status | " + TableCell(Safe(aiStatus)) + " |");
            builder.AppendLine("| Scope | Secondary redacted aggregate review only; the report determination and critical callouts are deterministic local telemetry. |");
            if (aiResult != null)
            {
                builder.AppendLine("| Flagged for review | " + (aiResult.Alertable ? "Yes" : "No") + " |");
                builder.AppendLine("| Cautious score | " + aiResult.Score.ToString(CultureInfo.InvariantCulture) + " |");
                builder.AppendLine("| Read | " + TableCell(Safe(aiResult.Title)) + " |");
                builder.AppendLine("| Summary | " + TableCell(Safe(aiResult.Summary)) + " |");
                builder.AppendLine("| Suggested action | " + TableCell(Safe(aiResult.RecommendedAction)) + " |");
            }
            else
            {
                builder.AppendLine("| Summary | No OpenAI daily analysis was included. |");
            }

            builder.AppendLine();
            builder.AppendLine("## Tuning Notes");
            AppendTuningNotes(builder, snapshot, metrics);
            return builder.ToString();
        }

        private void AppendQuickVerdict(StringBuilder builder, DailyReportSnapshot snapshot, DailyReportMetrics metrics)
        {
            builder.AppendLine("| Field | Value |");
            builder.AppendLine("| --- | --- |");
            builder.AppendLine("| Determination | " + TableCell(BuildOperatorVerdict(snapshot, metrics)) + " |");
            builder.AppendLine("| Compromise assessment | " + TableCell(BuildCompromiseAssessment(snapshot, metrics)) + " |");
            builder.AppendLine("| Confidence | " + TableCell(BuildConfidence(snapshot)) + " |");
            builder.AppendLine("| Analyzed window (system time) | " + TableCell(FormatSystemLocalTime(snapshot.WindowStartUtc) + " to " + FormatSystemLocalTime(snapshot.GeneratedUtc)) + " |");
            builder.AppendLine("| Generated (system time) | " + TableCell(FormatSystemLocalTime(snapshot.GeneratedUtc)) + " |");
            builder.AppendLine("| Basis | " + TableCell(BuildVerdictReason(snapshot, metrics)) + " |");
            builder.AppendLine("| Recommended next step | " + TableCell(BuildNextAction(metrics)) + " |");
        }

        private void AppendCriticalCallouts(StringBuilder builder, DailyReportSnapshot snapshot, DailyReportMetrics metrics)
        {
            List<DailySignalSummary> critical = BuildHighSignalSummaries(snapshot.Alerts, 90);
            if (critical.Count == 0)
            {
                builder.AppendLine("No critical-priority local signals were identified in the last 24 hours.");
                return;
            }

            builder.AppendLine("| Source / latest local time | Signal | Process / source | Count | Score | Assessment |");
            builder.AppendLine("| --- | --- | --- | --- | --- | --- |");

            int limit = Math.Min(5, critical.Count);
            for (int index = 0; index < limit; index++)
            {
                DailySignalSummary signal = critical[index];
                builder.AppendLine("| " + TableCell(FormatSystemLocalShort(signal.LatestTimestampUtc)) +
                    " | " + TableCell(signal.RuleId) +
                    " | " + TableCell(ProcessSummary(signal)) +
                    " | " + signal.Count.ToString(CultureInfo.InvariantCulture) +
                    " | " + signal.MaxScore.ToString(CultureInfo.InvariantCulture) +
                    " | " + TableCell(ExplainAlert(signal.SampleAlert)) + " |");
            }

            if (critical.Count > limit)
            {
                builder.AppendLine();
                builder.AppendLine((critical.Count - limit).ToString(CultureInfo.InvariantCulture) +
                    " additional critical-priority signal group(s) are summarized in the detail tables below.");
            }
        }

        private void AppendCoreReport(StringBuilder builder, DailyReportSnapshot snapshot, bool pretty, DailyReportMetrics metrics)
        {
            List<DailyAlertRecord> alerts = snapshot.Alerts;
            List<DailyAgentActivityRecord> agentActivities = snapshot.AgentActivities;

            if (pretty)
            {
                builder.AppendLine("## At A Glance");
                builder.AppendLine("| Item | Value |");
                builder.AppendLine("| --- | --- |");
                builder.AppendLine("| 24h alerts | " + metrics.WindowAlerts.ToString(CultureInfo.InvariantCulture) + " |");
                builder.AppendLine("| Critical / high priority | " + metrics.CriticalCount.ToString(CultureInfo.InvariantCulture) + " critical-priority, " + metrics.HighCount.ToString(CultureInfo.InvariantCulture) + " high-priority |");
                builder.AppendLine("| External-qualified before rate limits | " + metrics.ExternalQualified.ToString(CultureInfo.InvariantCulture) + " |");
                builder.AppendLine("| Health | " + TableCell(BuildHealthRead(snapshot)) + " |");
                builder.AppendLine("| Baseline learning | " + (snapshot.BaselineLearningMode ? "On" : "Off") + " |");
                builder.AppendLine("| Automation-context alerts | " + metrics.AgentContext.ToString(CultureInfo.InvariantCulture) + " |");
                builder.AppendLine("| Maintenance-context alerts | " + metrics.MaintenanceContext.ToString(CultureInfo.InvariantCulture) + " |");
                builder.AppendLine();

                builder.AppendLine("## Signal Summary");
                AppendBucketTable(builder, "Severity", BuildAlertBuckets(alerts, "severity"), 6);
                builder.AppendLine();
                AppendBucketTable(builder, "Top Categories", BuildAlertBuckets(alerts, "category"), 6);
                builder.AppendLine();
                AppendBucketTable(builder, "Top Rules", BuildAlertBuckets(alerts, "rule"), 6);
                builder.AppendLine();

                builder.AppendLine("## False Positive Context");
                AppendFalsePositiveContext(builder, snapshot, metrics);
                builder.AppendLine();

                builder.AppendLine("## High-Signal Details");
                AppendHighSignal(builder, alerts, 7);
                builder.AppendLine();

                builder.AppendLine("## Automation Activity");
                AppendAgentActivity(builder, agentActivities);
                return;
            }

            builder.AppendLine("[health]");
            builder.AppendLine("CurrentRunUptimeHours: " + snapshot.CurrentRunUptimeHours.ToString("0.00", CultureInfo.InvariantCulture));
            builder.AppendLine("CurrentRunPolls: " + snapshot.CurrentRunPolls.ToString(CultureInfo.InvariantCulture));
            builder.AppendLine("CurrentRunAlerts: " + snapshot.CurrentRunAlerts.ToString(CultureInfo.InvariantCulture));
            builder.AppendLine("CurrentRunPollFailures: " + snapshot.CurrentRunPollFailures.ToString(CultureInfo.InvariantCulture));
            builder.AppendLine("TotalPolls: " + snapshot.TotalPolls.ToString(CultureInfo.InvariantCulture));
            builder.AppendLine("TotalAlerts: " + snapshot.TotalAlerts.ToString(CultureInfo.InvariantCulture));
            builder.AppendLine("TotalPollFailures: " + snapshot.TotalPollFailures.ToString(CultureInfo.InvariantCulture));
            builder.AppendLine("ExternalSendFailures: " + snapshot.ExternalSendFailures.ToString(CultureInfo.InvariantCulture));
            builder.AppendLine("LastCleanStopUtc: " + Format(snapshot.LastCleanStopUtc));
            builder.AppendLine("BaselineLearningMode: " + snapshot.BaselineLearningMode);
            builder.AppendLine();

            builder.AppendLine("[alert_volume]");
            builder.AppendLine("WindowAlerts: " + alerts.Count.ToString(CultureInfo.InvariantCulture));
            builder.AppendLine("CriticalAlerts: " + metrics.CriticalCount.ToString(CultureInfo.InvariantCulture));
            builder.AppendLine("HighAlerts: " + metrics.HighCount.ToString(CultureInfo.InvariantCulture));
            builder.AppendLine("MediumAlerts: " + metrics.MediumCount.ToString(CultureInfo.InvariantCulture));
            builder.AppendLine("LowAlerts: " + metrics.LowCount.ToString(CultureInfo.InvariantCulture));
            builder.AppendLine("ExternalQualifiedBeforeRateLimits: " + metrics.ExternalQualified.ToString(CultureInfo.InvariantCulture));
            builder.AppendLine("MaintenanceContext: " + metrics.MaintenanceContext.ToString(CultureInfo.InvariantCulture));
            builder.AppendLine("AgentContext: " + metrics.AgentContext.ToString(CultureInfo.InvariantCulture));
            builder.AppendLine("HighestScore: " + metrics.HighestScore.ToString(CultureInfo.InvariantCulture));
            AppendBuckets(builder, "Severity", BuildAlertBuckets(alerts, "severity"), 6);
            AppendBuckets(builder, "Category", BuildAlertBuckets(alerts, "category"), 8);
            AppendBuckets(builder, "Rule", BuildAlertBuckets(alerts, "rule"), 10);
            AppendBuckets(builder, "ProcessFamily", BuildAlertBuckets(alerts, "process"), 8);
            builder.AppendLine();

            builder.AppendLine("[false_positive_context]");
            builder.AppendLine("BaselineLearningMode: " + snapshot.BaselineLearningMode);
            builder.AppendLine("VolumeAloneIsCompromise: false");
            builder.AppendLine("AutomationContextAlerts: " + metrics.AgentContext.ToString(CultureInfo.InvariantCulture));
            builder.AppendLine("MaintenanceContextAlerts: " + metrics.MaintenanceContext.ToString(CultureInfo.InvariantCulture));
            builder.AppendLine("TelemetryGaps: " + (snapshot.CurrentRunPollFailures > 0 || snapshot.TotalPollFailures > 0));
            builder.AppendLine();

            builder.AppendLine("[high_signal_review]");
            AppendHighSignal(builder, alerts, 10);
            builder.AppendLine();

            builder.AppendLine("[agent_activity]");
            builder.AppendLine("AgentActivityRecords: " + agentActivities.Count.ToString(CultureInfo.InvariantCulture));
            AppendAgentBuckets(builder, "AgentCommandCategory", BuildAgentBuckets(agentActivities, "command"), 8);
            AppendAgentBuckets(builder, "AgentEndpointCategory", BuildAgentBuckets(agentActivities, "endpoint"), 8);
            AppendAgentBuckets(builder, "AgentFileCategory", BuildAgentBuckets(agentActivities, "file"), 8);
        }

        private void AppendHighSignal(StringBuilder builder, List<DailyAlertRecord> alerts, int maxRows)
        {
            List<DailySignalSummary> highSignal = BuildHighSignalSummaries(alerts, 75);

            if (highSignal.Count == 0)
            {
                builder.AppendLine("None in the last 24 hours.");
                return;
            }

            builder.AppendLine("| Latest local time | Rule | Process / source | Count | Max score | Assessment |");
            builder.AppendLine("| --- | --- | --- | --- | --- | --- |");
            int limit = Math.Min(maxRows, highSignal.Count);
            for (int index = 0; index < limit; index++)
            {
                DailySignalSummary signal = highSignal[index];
                builder.AppendLine("| " + TableCell(FormatSystemLocalShort(signal.LatestTimestampUtc)) +
                    " | " + TableCell(signal.RuleId) +
                    " | " + TableCell(ProcessSummary(signal)) +
                    " | " + signal.Count.ToString(CultureInfo.InvariantCulture) +
                    " | " + signal.MaxScore.ToString(CultureInfo.InvariantCulture) +
                    " | " + TableCell(ExplainAlert(signal.SampleAlert)) + " |");
            }

            if (highSignal.Count > limit)
            {
                builder.AppendLine();
                builder.AppendLine((highSignal.Count - limit).ToString(CultureInfo.InvariantCulture) +
                    " additional high-signal alert(s) omitted from this quick report.");
            }
        }

        private void AppendTuningNotes(StringBuilder builder, DailyReportSnapshot snapshot, DailyReportMetrics metrics)
        {
            if (snapshot.Alerts.Count == 0)
            {
                builder.AppendLine("No alert-volume tuning suggested from the last 24 hours.");
                return;
            }

            builder.AppendLine("| Note | Why it matters |");
            builder.AppendLine("| --- | --- |");
            List<DailyReportBucket> ruleBuckets = BuildAlertBuckets(snapshot.Alerts, "rule");
            int notes = 0;
            foreach (DailyReportBucket bucket in ruleBuckets)
            {
                if (bucket.Count >= 3 && bucket.MaxScore <= 60)
                {
                    builder.AppendLine("| Repeated low-score rule | " + TableCell(bucket.Name + " appeared " +
                        bucket.Count.ToString(CultureInfo.InvariantCulture) +
                        " time(s); review local context before tuning thresholds or trust settings.") + " |");
                    notes++;
                    if (notes >= 3) break;
                }
            }

            if (snapshot.BaselineLearningMode)
            {
                builder.AppendLine("| Baseline learning is on | Keep external thresholds conservative; baseline discovery can inflate daily volume. |");
                notes++;
            }

            if (snapshot.TotalPollFailures > 0 || snapshot.CurrentRunPollFailures > 0)
            {
                builder.AppendLine("| Collector gaps observed | Check service permissions before interpreting missing telemetry as quietness. |");
                notes++;
            }

            if (notes == 0)
            {
                builder.AppendLine("| No obvious tuning action | Keep collecting baseline data and review only high-signal changes. |");
            }
        }

        private DailyReportMetrics CalculateMetrics(DailyReportSnapshot snapshot)
        {
            DailyReportMetrics metrics = new DailyReportMetrics();
            metrics.WindowAlerts = snapshot.Alerts.Count;

            foreach (DailyAlertRecord alert in snapshot.Alerts)
            {
                if (alert.Score > metrics.HighestScore) metrics.HighestScore = alert.Score;
                if (alert.Score >= 90) metrics.CriticalCount++;
                else if (alert.Score >= 75) metrics.HighCount++;
                else if (alert.Score >= 60) metrics.MediumCount++;
                else metrics.LowCount++;

                if (WouldQualifyForExternal(alert)) metrics.ExternalQualified++;
                if (alert.MaintenanceContext) metrics.MaintenanceContext++;
                if (alert.AgentContext) metrics.AgentContext++;
            }

            metrics.HighSignalCount = BuildHighSignalList(snapshot.Alerts, 75).Count;
            return metrics;
        }

        private List<DailyAlertRecord> BuildHighSignalList(List<DailyAlertRecord> alerts, int minimumScore)
        {
            List<DailyAlertRecord> highSignal = new List<DailyAlertRecord>();
            foreach (DailyAlertRecord alert in alerts)
            {
                if (alert.Score >= minimumScore ||
                    (minimumScore <= 75 &&
                        (StartsWith(alert.RuleId, "AUTH-REMOTE-") ||
                        StartsWith(alert.RuleId, "NET-LAN-") ||
                        StartsWith(alert.RuleId, "PERSIST-") ||
                        StartsWith(alert.RuleId, "FILE-") ||
                        StartsWith(alert.RuleId, "RAT-"))))
                {
                    highSignal.Add(alert);
                }
            }

            highSignal.Sort(delegate(DailyAlertRecord left, DailyAlertRecord right)
            {
                int scoreComparison = right.Score.CompareTo(left.Score);
                if (scoreComparison != 0) return scoreComparison;
                return right.TimestampUtc.CompareTo(left.TimestampUtc);
            });

            return highSignal;
        }

        private List<DailySignalSummary> BuildHighSignalSummaries(List<DailyAlertRecord> alerts, int minimumScore)
        {
            Dictionary<string, DailySignalSummary> summaries = new Dictionary<string, DailySignalSummary>(StringComparer.OrdinalIgnoreCase);
            foreach (DailyAlertRecord alert in BuildHighSignalList(alerts, minimumScore))
            {
                string key = alert.RuleId + "|" + alert.Title;
                DailySignalSummary summary;
                if (!summaries.TryGetValue(key, out summary))
                {
                    summary = new DailySignalSummary();
                    summary.RuleId = alert.RuleId;
                    summary.Title = alert.Title;
                    summary.SampleAlert = alert;
                    summary.LatestTimestampUtc = alert.TimestampUtc;
                    summary.ProcessCounts = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
                    summaries[key] = summary;
                }

                summary.Count++;
                AddProcessCount(summary, alert.ProcessFamily);
                if (alert.Score > summary.MaxScore)
                {
                    summary.MaxScore = alert.Score;
                    summary.SampleAlert = alert;
                }

                if (alert.TimestampUtc > summary.LatestTimestampUtc)
                {
                    summary.LatestTimestampUtc = alert.TimestampUtc;
                }
            }

            List<DailySignalSummary> result = new List<DailySignalSummary>(summaries.Values);
            result.Sort(delegate(DailySignalSummary left, DailySignalSummary right)
            {
                int scoreComparison = right.MaxScore.CompareTo(left.MaxScore);
                if (scoreComparison != 0) return scoreComparison;
                int countComparison = right.Count.CompareTo(left.Count);
                if (countComparison != 0) return countComparison;
                return right.LatestTimestampUtc.CompareTo(left.LatestTimestampUtc);
            });

            return result;
        }

        private static void AddProcessCount(DailySignalSummary summary, string processFamily)
        {
            if (summary == null) return;
            if (summary.ProcessCounts == null)
            {
                summary.ProcessCounts = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
            }

            string process = String.IsNullOrWhiteSpace(processFamily) ? "unknown" : processFamily;
            int count;
            summary.ProcessCounts.TryGetValue(process, out count);
            summary.ProcessCounts[process] = count + 1;
        }

        private static string ProcessSummary(DailySignalSummary summary)
        {
            if (summary == null || summary.ProcessCounts == null || summary.ProcessCounts.Count == 0)
            {
                return "unknown";
            }

            List<KeyValuePair<string, int>> values = new List<KeyValuePair<string, int>>(summary.ProcessCounts);
            values.Sort(delegate(KeyValuePair<string, int> left, KeyValuePair<string, int> right)
            {
                int countComparison = right.Value.CompareTo(left.Value);
                if (countComparison != 0) return countComparison;
                return String.Compare(left.Key, right.Key, StringComparison.OrdinalIgnoreCase);
            });

            string topProcess = values[0].Key;
            string result = topProcess + " (" + values[0].Value.ToString(CultureInfo.InvariantCulture) + ")";
            if (values.Count > 1)
            {
                result += ", +" + (values.Count - 1).ToString(CultureInfo.InvariantCulture) + " more";
            }

            return result;
        }

        private void AppendBucketTable(StringBuilder builder, string label, List<DailyReportBucket> buckets, int limit)
        {
            if (buckets.Count == 0)
            {
                builder.AppendLine("No " + label.ToLowerInvariant() + " records in this window.");
                return;
            }

            builder.AppendLine("| " + TableCell(label) + " | Count | Max score | Context |");
            builder.AppendLine("| --- | --- | --- | --- |");
            int count = Math.Min(limit, buckets.Count);
            for (int index = 0; index < count; index++)
            {
                DailyReportBucket bucket = buckets[index];
                builder.AppendLine("| " + TableCell(bucket.Name) +
                    " | " + bucket.Count.ToString(CultureInfo.InvariantCulture) +
                    " | " + bucket.MaxScore.ToString(CultureInfo.InvariantCulture) +
                    " | " + TableCell(BucketContext(bucket)) + " |");
            }
        }

        private void AppendFalsePositiveContext(StringBuilder builder, DailyReportSnapshot snapshot, DailyReportMetrics metrics)
        {
            builder.AppendLine("| Factor | Current context | How to read it |");
            builder.AppendLine("| --- | --- | --- |");
            builder.AppendLine("| Baseline learning | " + (snapshot.BaselineLearningMode ? "On" : "Off") +
                " | " + (snapshot.BaselineLearningMode
                    ? "Treat volume and newly observed behavior cautiously until the baseline settles."
                    : "Baseline learning is off; repeated new signals may deserve more weight.") + " |");
            builder.AppendLine("| Alert volume | " + metrics.WindowAlerts.ToString(CultureInfo.InvariantCulture) +
                " alert(s) | Volume alone is not evidence of compromise; rule type and context matter more. |");
            builder.AppendLine("| Automation context | " + metrics.AgentContext.ToString(CultureInfo.InvariantCulture) +
                " alert(s) | Known automation or administrative activity can explain some alert patterns. |");
            builder.AppendLine("| Maintenance context | " + metrics.MaintenanceContext.ToString(CultureInfo.InvariantCulture) +
                " alert(s) | Expected administrative activity should be reviewed, not counted as compromise by itself. |");
            builder.AppendLine("| Telemetry gaps | " + TableCell(BuildTelemetryGapText(snapshot)) +
                " | Gaps lower confidence; absence of alerts is weaker when collectors fail. |");
            builder.AppendLine("| AI context | Redacted aggregate only | The model sees trends, not full source-event fields such as paths, users, IPs, or command lines. |");
        }

        private void AppendAgentActivity(StringBuilder builder, List<DailyAgentActivityRecord> agentActivities)
        {
            if (agentActivities.Count == 0)
            {
                builder.AppendLine("No automation activity records in this window.");
                return;
            }

            builder.AppendLine("| Item | Value |");
            builder.AppendLine("| --- | --- |");
            builder.AppendLine("| Automation activity records | " + agentActivities.Count.ToString(CultureInfo.InvariantCulture) + " |");
            builder.AppendLine("| Command categories | " + TableCell(JoinBucketSummary(BuildAgentBuckets(agentActivities, "command"), 3)) + " |");
            builder.AppendLine("| Endpoint categories | " + TableCell(JoinBucketSummary(BuildAgentBuckets(agentActivities, "endpoint"), 3)) + " |");
            builder.AppendLine("| File categories | " + TableCell(JoinBucketSummary(BuildAgentBuckets(agentActivities, "file"), 3)) + " |");
        }

        private string BuildCompromiseAssessment(DailyReportSnapshot snapshot, DailyReportMetrics metrics)
        {
            if (snapshot.CurrentRunPollFailures > 0)
            {
                return "Unknown from this report because current telemetry has gaps; no confirmed compromise from available data.";
            }

            if (metrics.CriticalCount > 0)
            {
                return "No confirmed compromise; high-signal alerts require review before closing the assessment.";
            }

            if (metrics.HighCount > 0)
            {
                return "No confirmed compromise; review recommended for selected high-signal activity.";
            }

            return "No confirmed compromise from the last 24 hours of Arcane telemetry.";
        }

        private string BuildOperatorVerdict(DailyReportSnapshot snapshot, DailyReportMetrics metrics)
        {
            if (snapshot.CurrentRunPollFailures > 0) return "Telemetry gap - review collector health";
            if (metrics.CriticalCount > 0) return "Review required";
            if (metrics.HighCount > 0) return "Review recommended";
            if (metrics.WindowAlerts == 0) return "Quiet";
            return "No immediate findings";
        }

        private string BuildConfidence(DailyReportSnapshot snapshot)
        {
            if (snapshot.CurrentRunPollFailures > 0 || snapshot.TotalPollFailures > 0)
            {
                return "Low because collector failures were observed.";
            }

            if (snapshot.BaselineLearningMode)
            {
                return "Moderate-low because baseline learning mode is enabled.";
            }

            return "Moderate-high for the available telemetry.";
        }

        private string BuildVerdictReason(DailyReportSnapshot snapshot, DailyReportMetrics metrics)
        {
            string reason = metrics.CriticalCount.ToString(CultureInfo.InvariantCulture) + " critical-priority, " +
                metrics.HighCount.ToString(CultureInfo.InvariantCulture) + " high-priority, " +
                metrics.ExternalQualified.ToString(CultureInfo.InvariantCulture) + " external-qualified alert(s).";
            if (snapshot.BaselineLearningMode)
            {
                reason += " Baseline learning is enabled, so repeated volume is treated as context rather than evidence by itself.";
            }

            return reason;
        }

        private string BuildNextAction(DailyReportMetrics metrics)
        {
            if (metrics.CriticalCount > 0)
            {
                return "Review the priority callouts first, especially process ancestry, command context, and network destination.";
            }

            if (metrics.HighCount > 0)
            {
                return "Review the high-signal table and tune only after confirming expected software or administrative activity.";
            }

            return "No immediate action indicated; continue collecting baseline data and review new high-signal changes.";
        }

        private string BuildHealthRead(DailyReportSnapshot snapshot)
        {
            if (snapshot.CurrentRunPollFailures == 0 && snapshot.TotalPollFailures == 0 && snapshot.ExternalSendFailures == 0)
            {
                return "Collectors and external sends look healthy.";
            }

            return "Check collector/send health: current poll failures=" +
                snapshot.CurrentRunPollFailures.ToString(CultureInfo.InvariantCulture) +
                ", total poll failures=" + snapshot.TotalPollFailures.ToString(CultureInfo.InvariantCulture) +
                ", external send failures=" + snapshot.ExternalSendFailures.ToString(CultureInfo.InvariantCulture) + ".";
        }

        private static string BuildTelemetryGapText(DailyReportSnapshot snapshot)
        {
            if (snapshot.CurrentRunPollFailures == 0 && snapshot.TotalPollFailures == 0) return "None recorded";
            return "current=" + snapshot.CurrentRunPollFailures.ToString(CultureInfo.InvariantCulture) +
                ", total=" + snapshot.TotalPollFailures.ToString(CultureInfo.InvariantCulture);
        }

        private static string ExplainAlert(DailyAlertRecord alert)
        {
            if (StartsWith(alert.RuleId, "PS-ENCODED-")) return "Encoded or obfuscated PowerShell; review command origin and parent process.";
            if (StartsWith(alert.RuleId, "NET-C2-BEACON")) return "Beacon-like timing; confirm process and destination before assuming C2.";
            if (StartsWith(alert.RuleId, "RAT-")) return "RAT/LOLBin-style egress; verify command line and destination.";
            if (StartsWith(alert.RuleId, "AUTH-REMOTE-")) return "Remote auth plus privilege context; verify account and source.";
            if (StartsWith(alert.RuleId, "NET-LAN-")) return "LAN lateral/admin-port pattern; verify peer host and process.";
            if (StartsWith(alert.RuleId, "FILE-")) return "High-risk file write or drop-execute pattern; verify writer and path.";
            if (StartsWith(alert.RuleId, "PERSIST-")) return "Persistence change; verify expected administrative or software activity.";
            if (alert.Score >= 90) return "Critical-priority local signal; inspect source-event context before declaring compromise.";
            if (alert.Score >= 75) return "High signal; review source-event context.";
            return SanitizeText(alert.Title);
        }

        private static string BucketContext(DailyReportBucket bucket)
        {
            List<string> parts = new List<string>();
            if (bucket.AgentContext > 0) parts.Add("automation " + bucket.AgentContext.ToString(CultureInfo.InvariantCulture));
            if (bucket.MaintenanceContext > 0) parts.Add("maintenance " + bucket.MaintenanceContext.ToString(CultureInfo.InvariantCulture));
            return parts.Count == 0 ? "none" : String.Join("; ", parts.ToArray());
        }

        private static string JoinBucketSummary(List<DailyReportBucket> buckets, int limit)
        {
            if (buckets.Count == 0) return "none";

            List<string> parts = new List<string>();
            int count = Math.Min(limit, buckets.Count);
            for (int index = 0; index < count; index++)
            {
                DailyReportBucket bucket = buckets[index];
                parts.Add(bucket.Name + " (" + bucket.Count.ToString(CultureInfo.InvariantCulture) + ")");
            }

            return String.Join(", ", parts.ToArray());
        }

        private List<DailyAlertRecord> LoadAlerts(DateTime cutoffUtc)
        {
            List<DailyAlertRecord> result = new List<DailyAlertRecord>();
            string path = Path.Combine(config.LogDirectory, "ArcaneAlerts.jsonl");
            if (!File.Exists(path)) return result;

            JavaScriptSerializer serializer = new JavaScriptSerializer();
            foreach (string line in File.ReadLines(path))
            {
                DailyAlertRecord record = ParseAlert(serializer, line);
                if (record == null || record.TimestampUtc < cutoffUtc) continue;
                if (IsReportExcludedRule(record.RuleId)) continue;
                result.Add(record);
            }

            return result;
        }

        private List<DailyAgentActivityRecord> LoadAgentActivities(DateTime cutoffUtc)
        {
            List<DailyAgentActivityRecord> result = new List<DailyAgentActivityRecord>();
            if (!File.Exists(config.AgentActivityLedgerFile)) return result;

            JavaScriptSerializer serializer = new JavaScriptSerializer();
            foreach (string line in File.ReadLines(config.AgentActivityLedgerFile))
            {
                DailyAgentActivityRecord record = ParseAgentActivity(serializer, line);
                if (record == null || record.TimestampUtc < cutoffUtc) continue;
                result.Add(record);
            }

            return result;
        }

        private DailyAlertRecord ParseAlert(JavaScriptSerializer serializer, string line)
        {
            try
            {
                IDictionary parsed = serializer.DeserializeObject(line) as IDictionary;
                if (parsed == null) return null;

                DateTime timestampUtc;
                if (!TryParseUtc(Read(parsed, "timestamp_utc"), out timestampUtc)) return null;

                DailyAlertRecord record = new DailyAlertRecord();
                record.TimestampUtc = timestampUtc;
                record.RuleId = NullToUnknown(Read(parsed, "rule_id"));
                record.Category = NullToUnknown(Read(parsed, "category"));
                if (record.Category.Equals("unknown", StringComparison.OrdinalIgnoreCase))
                {
                    record.Category = AlertRuleCatalog.CategoryFor(record.RuleId);
                }

                record.Severity = NullToUnknown(Read(parsed, "severity"));
                record.Score = ReadInt(parsed, "score");
                record.Title = SanitizeText(Read(parsed, "title"));
                record.MaintenanceContext = ReadBool(parsed, "maintenance_context");
                record.ProcessFamily = ProcessFamily(Read(parsed, "entity"));
                record.AgentContext = HasAgentContext(parsed);
                return record;
            }
            catch
            {
                return null;
            }
        }

        private static DailyAgentActivityRecord ParseAgentActivity(JavaScriptSerializer serializer, string line)
        {
            try
            {
                IDictionary parsed = serializer.DeserializeObject(line) as IDictionary;
                if (parsed == null) return null;

                DateTime timestampUtc;
                if (!TryParseUtc(Read(parsed, "timestamp_utc"), out timestampUtc)) return null;

                DailyAgentActivityRecord record = new DailyAgentActivityRecord();
                record.TimestampUtc = timestampUtc;
                record.RuleId = NullToUnknown(Read(parsed, "rule_id"));
                record.Score = ReadInt(parsed, "score");
                record.CommandCategory = NullToUnknown(Read(parsed, "command_category"));
                record.EndpointCategory = NullToUnknown(Read(parsed, "endpoint_category"));
                record.FileCategory = NullToUnknown(Read(parsed, "file_category"));
                record.ProcessFamily = NullToUnknown(Read(parsed, "process_family"));
                record.MaintenanceContext = ReadBool(parsed, "maintenance_context");
                return record;
            }
            catch
            {
                return null;
            }
        }

        private List<DailyReportBucket> BuildAlertBuckets(List<DailyAlertRecord> records, string field)
        {
            Dictionary<string, DailyReportBucket> buckets = new Dictionary<string, DailyReportBucket>(StringComparer.OrdinalIgnoreCase);
            foreach (DailyAlertRecord record in records)
            {
                string name = AlertBucketName(record, field);
                DailyReportBucket bucket;
                if (!buckets.TryGetValue(name, out bucket))
                {
                    bucket = new DailyReportBucket();
                    bucket.Name = name;
                    buckets[name] = bucket;
                }

                bucket.Count++;
                if (record.Score > bucket.MaxScore) bucket.MaxScore = record.Score;
                if (record.MaintenanceContext) bucket.MaintenanceContext++;
                if (record.AgentContext) bucket.AgentContext++;
            }

            return SortBuckets(buckets);
        }

        private List<DailyReportBucket> BuildAgentBuckets(List<DailyAgentActivityRecord> records, string field)
        {
            Dictionary<string, DailyReportBucket> buckets = new Dictionary<string, DailyReportBucket>(StringComparer.OrdinalIgnoreCase);
            foreach (DailyAgentActivityRecord record in records)
            {
                string name = AgentBucketName(record, field);
                DailyReportBucket bucket;
                if (!buckets.TryGetValue(name, out bucket))
                {
                    bucket = new DailyReportBucket();
                    bucket.Name = name;
                    buckets[name] = bucket;
                }

                bucket.Count++;
                if (record.Score > bucket.MaxScore) bucket.MaxScore = record.Score;
                if (record.MaintenanceContext) bucket.MaintenanceContext++;
            }

            return SortBuckets(buckets);
        }

        private static List<DailyReportBucket> SortBuckets(Dictionary<string, DailyReportBucket> buckets)
        {
            List<DailyReportBucket> result = new List<DailyReportBucket>(buckets.Values);
            result.Sort(delegate(DailyReportBucket left, DailyReportBucket right)
            {
                int countComparison = right.Count.CompareTo(left.Count);
                if (countComparison != 0) return countComparison;
                int scoreComparison = right.MaxScore.CompareTo(left.MaxScore);
                if (scoreComparison != 0) return scoreComparison;
                return String.Compare(left.Name, right.Name, StringComparison.OrdinalIgnoreCase);
            });
            return result;
        }

        private static void AppendBuckets(StringBuilder builder, string label, List<DailyReportBucket> buckets, int limit)
        {
            if (buckets.Count == 0)
            {
                builder.AppendLine(label + ": none");
                return;
            }

            int count = Math.Min(limit, buckets.Count);
            for (int index = 0; index < count; index++)
            {
                DailyReportBucket bucket = buckets[index];
                builder.AppendLine(label + ": " + bucket.Name +
                    " count=" + bucket.Count.ToString(CultureInfo.InvariantCulture) +
                    " max=" + bucket.MaxScore.ToString(CultureInfo.InvariantCulture) +
                    " maintenance_context=" + bucket.MaintenanceContext.ToString(CultureInfo.InvariantCulture) +
                    " agent_context=" + bucket.AgentContext.ToString(CultureInfo.InvariantCulture));
            }
        }

        private static void AppendAgentBuckets(StringBuilder builder, string label, List<DailyReportBucket> buckets, int limit)
        {
            if (buckets.Count == 0)
            {
                builder.AppendLine(label + ": none");
                return;
            }

            int count = Math.Min(limit, buckets.Count);
            for (int index = 0; index < count; index++)
            {
                DailyReportBucket bucket = buckets[index];
                builder.AppendLine(label + ": " + bucket.Name +
                    " count=" + bucket.Count.ToString(CultureInfo.InvariantCulture) +
                    " max=" + bucket.MaxScore.ToString(CultureInfo.InvariantCulture) +
                    " maintenance_context=" + bucket.MaintenanceContext.ToString(CultureInfo.InvariantCulture));
            }
        }

        private bool WouldQualifyForExternal(DailyAlertRecord record)
        {
            if (record.Score < config.MinimumEmailScore) return false;
            if (record.MaintenanceContext && record.Score < config.MaintenanceContextExternalAlertMinimumScore) return false;
            if (config.BaselineLearningMode && record.Score < config.BaselineLearningEmailMinimumScore) return false;
            return true;
        }

        private string Assess(DailyReportSnapshot snapshot)
        {
            int maxScore = 0;
            int high = 0;
            int critical = 0;
            foreach (DailyAlertRecord alert in snapshot.Alerts)
            {
                if (alert.Score > maxScore) maxScore = alert.Score;
                if (alert.Score >= 90) critical++;
                else if (alert.Score >= 75) high++;
            }

            if (critical > 0 || snapshot.CurrentRunPollFailures > 0) return "Needs review";
            if (high > 0 || maxScore >= 70) return "Review recommended";
            if (snapshot.Alerts.Count == 0) return "Quiet";
            return "No immediate findings";
        }

        private bool IsReportExcludedRule(string ruleId)
        {
            if (String.IsNullOrWhiteSpace(ruleId)) return false;
            if (config.OpenAIAnalysisExcludedRuleIds.Contains(ruleId)) return true;
            return ruleId.Equals("SERVICE-DAILY-SUMMARY", StringComparison.OrdinalIgnoreCase);
        }

        private static string AlertBucketName(DailyAlertRecord record, string field)
        {
            if (field.Equals("severity", StringComparison.OrdinalIgnoreCase)) return record.Severity;
            if (field.Equals("category", StringComparison.OrdinalIgnoreCase)) return record.Category;
            if (field.Equals("rule", StringComparison.OrdinalIgnoreCase)) return record.RuleId;
            if (field.Equals("process", StringComparison.OrdinalIgnoreCase)) return record.ProcessFamily;
            return "unknown";
        }

        private static string AgentBucketName(DailyAgentActivityRecord record, string field)
        {
            if (field.Equals("command", StringComparison.OrdinalIgnoreCase)) return record.CommandCategory;
            if (field.Equals("endpoint", StringComparison.OrdinalIgnoreCase)) return record.EndpointCategory;
            if (field.Equals("file", StringComparison.OrdinalIgnoreCase)) return record.FileCategory;
            if (field.Equals("process", StringComparison.OrdinalIgnoreCase)) return record.ProcessFamily;
            return "unknown";
        }

        private static string ProcessFamily(string entity)
        {
            string value = FirstNonEmpty(
                ExtractToken(entity, "process"),
                FirstNonEmpty(
                    ExtractToken(entity, "image"),
                    FirstNonEmpty(
                        ExtractToken(entity, "process_path"),
                        ExtractToken(entity, "host_application"))));
            if (String.IsNullOrWhiteSpace(value)) return "unknown";

            try
            {
                string fileName = Path.GetFileName(value);
                if (!String.IsNullOrWhiteSpace(fileName)) value = fileName;
            }
            catch
            {
            }

            return SanitizeProcessToken(value);
        }

        private static bool HasAgentContext(IDictionary parsed)
        {
            if (ContainsIgnoreCase(Read(parsed, "body"), "AgentContext: involved")) return true;
            if (ContainsIgnoreCase(Read(parsed, "entity"), "agent_context=involved")) return true;
            return ContainsIgnoreCase(Read(parsed, "why"), "agent-") ||
                ContainsIgnoreCase(Read(parsed, "why"), "unattended-agent");
        }

        private static string ExtractToken(string text, string key)
        {
            if (String.IsNullOrWhiteSpace(text) || String.IsNullOrWhiteSpace(key)) return "";
            string prefix = key + "=";
            int index = text.IndexOf(prefix, StringComparison.OrdinalIgnoreCase);
            if (index < 0) return "";

            int start = index + prefix.Length;
            int end;
            if (start < text.Length && text[start] == '"')
            {
                start++;
                end = text.IndexOf('"', start);
            }
            else
            {
                end = text.IndexOf(' ', start);
            }

            if (end < 0) end = text.Length;
            return text.Substring(start, end - start).Trim().Trim('"');
        }

        private static string FirstNonEmpty(string first, string second)
        {
            return !String.IsNullOrWhiteSpace(first) ? first : second;
        }

        private static string Read(IDictionary parsed, string key)
        {
            if (!parsed.Contains(key) || parsed[key] == null) return "";
            return parsed[key].ToString();
        }

        private static int ReadInt(IDictionary parsed, string key)
        {
            if (!parsed.Contains(key) || parsed[key] == null) return 0;
            int value;
            return Int32.TryParse(parsed[key].ToString(), out value) ? value : 0;
        }

        private static bool ReadBool(IDictionary parsed, string key)
        {
            if (!parsed.Contains(key) || parsed[key] == null) return false;
            bool value;
            return Boolean.TryParse(parsed[key].ToString(), out value) && value;
        }

        private static bool TryParseUtc(string value, out DateTime result)
        {
            result = DateTime.MinValue;
            if (String.IsNullOrWhiteSpace(value)) return false;
            DateTime parsed;
            if (!DateTime.TryParse(value, CultureInfo.InvariantCulture, DateTimeStyles.AdjustToUniversal, out parsed)) return false;
            result = parsed.ToUniversalTime();
            return true;
        }

        private static bool StartsWith(string value, string prefix)
        {
            return value != null && value.StartsWith(prefix, StringComparison.OrdinalIgnoreCase);
        }

        private static bool ContainsIgnoreCase(string text, string value)
        {
            return !String.IsNullOrWhiteSpace(text) &&
                !String.IsNullOrWhiteSpace(value) &&
                text.IndexOf(value, StringComparison.OrdinalIgnoreCase) >= 0;
        }

        private static string Limit(string value, int maxChars)
        {
            if (String.IsNullOrWhiteSpace(value) || maxChars <= 0 || value.Length <= maxChars) return value;
            return value.Substring(value.Length - maxChars);
        }

        private static string NullToUnknown(string value)
        {
            return String.IsNullOrWhiteSpace(value) ? "unknown" : value;
        }

        private static string Safe(string value)
        {
            return value == null ? "" : value;
        }

        private static string TableCell(string value)
        {
            string result = Safe(value)
                .Replace("|", "/")
                .Replace("\r", " ")
                .Replace("\n", " ")
                .Trim();
            if (result.Length == 0) return "n/a";
            return result.Length <= 420 ? result : result.Substring(0, 417).TrimEnd() + "...";
        }

        private static string SanitizeToken(string value)
        {
            if (String.IsNullOrWhiteSpace(value)) return "unknown";
            string sanitized = SanitizeText(value)
                .Replace(" ", "_")
                .Replace(",", "_")
                .Replace(";", "_")
                .Replace("|", "_");
            return sanitized.Length <= 80 ? sanitized : sanitized.Substring(0, 80);
        }

        private static string SanitizeProcessToken(string value)
        {
            if (String.IsNullOrWhiteSpace(value)) return "unknown";
            string result = value.Trim()
                .Replace("\\", "/")
                .Replace("\"", "")
                .Replace(",", "_")
                .Replace(";", "_")
                .Replace("|", "_")
                .Replace("\r", "")
                .Replace("\n", "");
            return result.Length <= 80 ? result : result.Substring(0, 80);
        }

        private static string SanitizeText(string value)
        {
            if (String.IsNullOrWhiteSpace(value)) return "";
            string result = value;
            result = Regex.Replace(result, "(?i)(api[_-]?key|apikey|token|secret|password|passwd|pwd|authorization|client_secret|access_token|refresh_token)\\s*[:=]\\s*[^\\s,;\\}\\]]+", "$1=[redacted-secret]");
            result = Regex.Replace(result, "[A-Za-z0-9._%+\\-]+@[A-Za-z0-9.\\-]+\\.[A-Za-z]{2,}", "[redacted-email]");
            result = Regex.Replace(result, "(?i)https?://[^\\s\"'<>]+", "[redacted-url]");
            result = Regex.Replace(result, "(?i)\\b(?:[a-z0-9](?:[a-z0-9\\-]{0,61}[a-z0-9])?\\.)+[a-z]{2,}\\b", "[redacted-domain]");
            result = Regex.Replace(result, "\\b(?:\\d{1,3}\\.){3}\\d{1,3}\\b", "[redacted-ip]");
            result = Regex.Replace(result, "(?i)[A-Z]:\\\\[^\\s|,\"']+", "[redacted-path]");
            result = Regex.Replace(result, "(?i)(user|subject|target)=([^\\s|,]+)", "$1=[redacted-account]");
            result = Regex.Replace(result, "(?i)(command_line|parent_command_line|script_block|decodedpreview)=([^|]+)", "$1=[redacted]");
            return result.Trim();
        }

        private static string Format(DateTime? value)
        {
            return value.HasValue ? Format(value.Value) : "";
        }

        private static string Format(DateTime value)
        {
            return value.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ", CultureInfo.InvariantCulture);
        }

        private static string FormatSystemLocalTime(DateTime timestampUtc)
        {
            DateTime utc = timestampUtc.Kind == DateTimeKind.Utc
                ? timestampUtc
                : timestampUtc.ToUniversalTime();
            TimeZoneInfo zone = TimeZoneInfo.Local;
            DateTime local = TimeZoneInfo.ConvertTimeFromUtc(utc, zone);
            TimeSpan offset = zone.GetUtcOffset(utc);
            DateTimeOffset localWithOffset = new DateTimeOffset(local, offset);
            return localWithOffset.ToString("yyyy-MM-ddTHH:mm:ss zzz", CultureInfo.InvariantCulture) +
                " (" + zone.Id + ")";
        }

        private static string FormatSystemLocalShort(DateTime timestampUtc)
        {
            DateTime utc = timestampUtc.Kind == DateTimeKind.Utc
                ? timestampUtc
                : timestampUtc.ToUniversalTime();
            TimeZoneInfo zone = TimeZoneInfo.Local;
            DateTime local = TimeZoneInfo.ConvertTimeFromUtc(utc, zone);
            TimeSpan offset = zone.GetUtcOffset(utc);
            DateTimeOffset localWithOffset = new DateTimeOffset(local, offset);
            return localWithOffset.ToString("yyyy-MM-dd HH:mm zzz", CultureInfo.InvariantCulture);
        }
    }

    internal sealed class DailyReportSnapshot
    {
        public DateTime GeneratedUtc;
        public DateTime WindowStartUtc;
        public string RunId;
        public double CurrentRunUptimeHours;
        public long CurrentRunPolls;
        public long CurrentRunAlerts;
        public long CurrentRunPollFailures;
        public long TotalPolls;
        public long TotalAlerts;
        public long TotalPollFailures;
        public long ExternalSendFailures;
        public DateTime? LastCleanStopUtc;
        public bool BaselineLearningMode;
        public string ScheduledLocalTime;
        public string Assessment;
        public readonly List<DailyAlertRecord> Alerts = new List<DailyAlertRecord>();
        public readonly List<DailyAgentActivityRecord> AgentActivities = new List<DailyAgentActivityRecord>();
    }

    internal sealed class DailyAlertRecord
    {
        public DateTime TimestampUtc;
        public string RuleId;
        public string Category;
        public string Severity;
        public int Score;
        public string Title;
        public string ProcessFamily;
        public bool MaintenanceContext;
        public bool AgentContext;
    }

    internal sealed class DailyAgentActivityRecord
    {
        public DateTime TimestampUtc;
        public string RuleId;
        public int Score;
        public string CommandCategory;
        public string EndpointCategory;
        public string FileCategory;
        public string ProcessFamily;
        public bool MaintenanceContext;
    }

    internal sealed class DailyReportBucket
    {
        public string Name;
        public int Count;
        public int MaxScore;
        public int MaintenanceContext;
        public int AgentContext;
    }

    internal sealed class DailySignalSummary
    {
        public string RuleId;
        public string Title;
        public int Count;
        public int MaxScore;
        public DateTime LatestTimestampUtc;
        public DailyAlertRecord SampleAlert;
        public Dictionary<string, int> ProcessCounts;
    }

    internal sealed class DailyReportMetrics
    {
        public int WindowAlerts;
        public int CriticalCount;
        public int HighCount;
        public int MediumCount;
        public int LowCount;
        public int ExternalQualified;
        public int MaintenanceContext;
        public int AgentContext;
        public int HighestScore;
        public int HighSignalCount;
    }
}
