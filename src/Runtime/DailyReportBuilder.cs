using System;
using System.Collections;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Text;
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
            snapshot.HostIdentity = HostIdentity.Current();
            snapshot.BaselineLearningMode = config.BaselineLearningMode;
            snapshot.ScheduledLocalTime = DailySummarySchedule.Describe(config);
            snapshot.Alerts.AddRange(LoadAlerts(snapshot.WindowStartUtc));
            snapshot.AgentActivities.AddRange(LoadAgentActivities(snapshot.WindowStartUtc));
            snapshot.Assessment = Assess(snapshot);
            return snapshot;
        }

        public string BuildAiPayload(DailyReportSnapshot snapshot)
        {
            StringBuilder builder = new StringBuilder();
            DailyReportMetrics metrics = CalculateMetrics(snapshot);
            builder.AppendLine("arcane_edr_daily_report_payload");
            builder.AppendLine("privacy_mode=redacted_aggregate_summary_only");
            builder.AppendLine("omitted_fields=alert_body,entity,command_line,script_block,user,path,ip,url,email,secrets");
            builder.AppendLine("analysis_guardrails=do_not_treat_alert_volume_alone_as_compromise;weigh_baseline_learning_maintenance_automation_context_and_telemetry_gaps;state_uncertainty_when_source_context_is_missing");
            builder.AppendLine("primary_review_scope=actionable_non_policy_suppressed_alerts");
            builder.AppendLine("policy_suppressed_scope=retained_local_audit_context_not_primary_review_queue");
            builder.AppendLine("recipient_question=is_compromise_confirmed_or_review_required");
            builder.AppendLine("report_verdict=" + SanitizeToken(BuildOperatorVerdict(snapshot, metrics)));
            builder.AppendLine("compromise_assessment=" + SanitizeText(BuildCompromiseAssessment(snapshot, metrics)));
            builder.AppendLine("confidence=" + SanitizeToken(BuildConfidence(snapshot)));
            builder.AppendLine("analyzed_window_system_time=" + SanitizeText(FormatSystemLocalTime(snapshot.WindowStartUtc) + " to " + FormatSystemLocalTime(snapshot.GeneratedUtc)));
            builder.AppendLine("generated_system_time=" + SanitizeText(FormatSystemLocalTime(snapshot.GeneratedUtc)));
            builder.AppendLine("analyzed_window_utc=" + UtcTimestamp.Format(snapshot.WindowStartUtc) + " to " + UtcTimestamp.Format(snapshot.GeneratedUtc));
            AppendCoreReport(builder, snapshot, false, metrics);
            return Limit(builder.ToString(), config.AIAnalysisMaxChars);
        }

        public string BuildReport(DailyReportSnapshot snapshot, AiAnalysisResult aiResult, string aiStatus)
        {
            StringBuilder builder = new StringBuilder();
            DailyReportMetrics metrics = CalculateMetrics(snapshot);
            if (DailyReportSectionEnabled("QuickVerdict"))
            {
                AppendQuickVerdict(builder, snapshot, metrics);
                builder.AppendLine();
            }

            if (DailyReportSectionEnabled("CriticalCallouts"))
            {
                builder.AppendLine("## Critical Callouts");
                AppendCriticalCallouts(builder, snapshot, metrics);
                builder.AppendLine();
            }

            AppendCoreReport(builder, snapshot, true, metrics);

            if (DailyReportSectionEnabled("AIReview"))
            {
                builder.AppendLine();
                builder.AppendLine("## AI Review");
                builder.AppendLine("| Field | Value |");
                builder.AppendLine("| --- | --- |");
                builder.AppendLine("| Status | " + TableCell(TextFormatting.EmptyIfNull(aiStatus)) + " |");
                builder.AppendLine("| Scope | Secondary redacted aggregate review only; the report determination and critical callouts are deterministic local telemetry. |");
                if (aiResult != null)
                {
                    builder.AppendLine("| Providers | " + TableCell(TextFormatting.EmptyIfNull(aiResult.ProviderName)) + " |");
                    builder.AppendLine("| Flagged for review | " + (aiResult.Alertable ? "Yes" : "No") + " |");
                    builder.AppendLine("| Cautious score | " + aiResult.Score.ToString(CultureInfo.InvariantCulture) + " |");
                    builder.AppendLine("| Read | " + TableCell(TextFormatting.EmptyIfNull(aiResult.Title)) + " |");
                    builder.AppendLine("| Summary | " + TableCell(TextFormatting.EmptyIfNull(aiResult.Summary)) + " |");
                    builder.AppendLine("| Suggested action | " + TableCell(TextFormatting.EmptyIfNull(aiResult.RecommendedAction)) + " |");

                    if (aiResult.ProviderOutcomes.Count > 1)
                    {
                        builder.AppendLine();
                        builder.AppendLine("| Provider | Status | Flagged | Score | Read |");
                        builder.AppendLine("| --- | --- | --- | --- | --- |");
                        foreach (AiProviderAnalysisOutcome outcome in aiResult.ProviderOutcomes)
                        {
                            builder.AppendLine("| " + TableCell(TextFormatting.EmptyIfNull(outcome.ProviderName)) +
                                " | " + TableCell(TextFormatting.EmptyIfNull(outcome.Status)) +
                                " | " + (outcome.Alertable ? "Yes" : "No") +
                                " | " + outcome.Score.ToString(CultureInfo.InvariantCulture) +
                                " | " + TableCell(TextFormatting.EmptyIfNull(outcome.Title)) + " |");
                        }
                    }
                }
                else
                {
                    builder.AppendLine("| Summary | No AI daily analysis was included. |");
                }
            }

            if (DailyReportSectionEnabled("TuningNotes"))
            {
                builder.AppendLine();
                builder.AppendLine("## Tuning Notes");
                AppendTuningNotes(builder, snapshot, metrics);
            }

            return builder.ToString();
        }

        public string BuildArchiveJson(DailyReportSnapshot snapshot, AiAnalysisResult aiResult, string aiStatus)
        {
            DailyReportMetrics metrics = CalculateMetrics(snapshot);
            Dictionary<string, object> root = new Dictionary<string, object>(StringComparer.OrdinalIgnoreCase);
            root["schema"] = "arcane_daily_report_v1";
            root["generated_utc"] = UtcTimestamp.Format(snapshot.GeneratedUtc);
            root["window_start_utc"] = UtcTimestamp.Format(snapshot.WindowStartUtc);
            root["window_end_utc"] = UtcTimestamp.Format(snapshot.GeneratedUtc);
            root["generated_system_time"] = FormatSystemLocalTime(snapshot.GeneratedUtc);
            root["window_system_time"] = FormatSystemLocalTime(snapshot.WindowStartUtc) + " to " + FormatSystemLocalTime(snapshot.GeneratedUtc);
            root["host_identity"] = BuildHostIdentityObject(snapshot.HostIdentity);
            root["scheduled_local_time"] = snapshot.ScheduledLocalTime;
            root["run_id"] = snapshot.RunId;
            root["assessment"] = snapshot.Assessment;
            root["determination"] = BuildOperatorVerdict(snapshot, metrics);
            root["compromise_assessment"] = BuildCompromiseAssessment(snapshot, metrics);
            root["confidence"] = BuildConfidence(snapshot);
            root["recommended_next_step"] = BuildNextAction(metrics);
            root["sections"] = new List<string>(config.DailyReportSections);
            root["metrics"] = BuildMetricsObject(metrics);
            root["health"] = BuildHealthObject(snapshot);
            root["top_severities"] = BuildBucketObjects(BuildAlertBuckets(ActionableAlerts(snapshot.Alerts), "severity"), config.DailyReportBucketRows);
            root["top_categories"] = BuildBucketObjects(BuildAlertBuckets(ActionableAlerts(snapshot.Alerts), "category"), config.DailyReportBucketRows);
            root["top_rules"] = BuildBucketObjects(BuildAlertBuckets(ActionableAlerts(snapshot.Alerts), "rule"), config.DailyReportBucketRows);
            root["high_signal"] = BuildSignalObjects(BuildHighSignalSummaries(snapshot.Alerts, 75, true), config.DailyReportHighSignalRows);
            root["automation_activity"] = BuildAgentActivityObject(snapshot.AgentActivities);
            root["ai_review"] = BuildAiObject(aiResult, aiStatus);

            JavaScriptSerializer serializer = new JavaScriptSerializer();
            return serializer.Serialize(root);
        }

        private void AppendQuickVerdict(StringBuilder builder, DailyReportSnapshot snapshot, DailyReportMetrics metrics)
        {
            builder.AppendLine("| Field | Value |");
            builder.AppendLine("| --- | --- |");
            builder.AppendLine("| Determination | " + TableCell(BuildOperatorVerdict(snapshot, metrics)) + " |");
            builder.AppendLine("| Compromise assessment | " + TableCell(BuildCompromiseAssessment(snapshot, metrics)) + " |");
            builder.AppendLine("| Confidence | " + TableCell(BuildConfidence(snapshot)) + " |");
            builder.AppendLine("| Local machine | " + TableCell(HostMachineText(snapshot.HostIdentity)) + " |");
            builder.AppendLine("| Local IP addresses | " + TableCell(HostIpText(snapshot.HostIdentity)) + " |");
            builder.AppendLine("| Analyzed window (system time) | " + TableCell(FormatSystemLocalTime(snapshot.WindowStartUtc) + " to " + FormatSystemLocalTime(snapshot.GeneratedUtc)) + " |");
            builder.AppendLine("| Generated (system time) | " + TableCell(FormatSystemLocalTime(snapshot.GeneratedUtc)) + " |");
            builder.AppendLine("| Basis | " + TableCell(BuildVerdictReason(snapshot, metrics)) + " |");
            builder.AppendLine("| Recommended next step | " + TableCell(BuildNextAction(metrics)) + " |");
        }

        private void AppendCriticalCallouts(StringBuilder builder, DailyReportSnapshot snapshot, DailyReportMetrics metrics)
        {
            List<DailySignalSummary> critical = BuildHighSignalSummaries(snapshot.Alerts, 90, true);
            if (critical.Count == 0)
            {
                builder.AppendLine("No actionable critical-priority signals were identified in the last 24 hours.");
                if (metrics.PolicySuppressedCriticalCount > 0)
                {
                    builder.AppendLine();
                    builder.AppendLine(metrics.PolicySuppressedCriticalCount.ToString(CultureInfo.InvariantCulture) +
                        " policy-suppressed critical-priority local record(s) were retained for audit and omitted from priority callouts.");
                }
                return;
            }

            builder.AppendLine("| Source / latest local time | Signal | Process / source | Count | Score | Assessment |");
            builder.AppendLine("| --- | --- | --- | --- | --- | --- |");

            int limit = Math.Min(config.DailyReportCriticalCalloutRows, critical.Count);
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
                if (DailyReportSectionEnabled("AtAGlance"))
                {
                    builder.AppendLine("## At A Glance");
                    builder.AppendLine("| Item | Value |");
                    builder.AppendLine("| --- | --- |");
                    builder.AppendLine("| 24h alerts | " + metrics.WindowAlerts.ToString(CultureInfo.InvariantCulture) + " |");
                    builder.AppendLine("| Actionable critical / high | " + metrics.CriticalCount.ToString(CultureInfo.InvariantCulture) + " critical-priority, " + metrics.HighCount.ToString(CultureInfo.InvariantCulture) + " high-priority |");
                    builder.AppendLine("| Local critical / high retained | " + metrics.LocalCriticalCount.ToString(CultureInfo.InvariantCulture) + " critical-priority, " + metrics.LocalHighCount.ToString(CultureInfo.InvariantCulture) + " high-priority |");
                    builder.AppendLine("| Policy-suppressed local evidence | " + PolicySuppressedSummary(metrics) + " |");
                    builder.AppendLine("| External-qualified before rate limits | " + metrics.ExternalQualified.ToString(CultureInfo.InvariantCulture) + " |");
                    builder.AppendLine("| Health | " + TableCell(BuildHealthRead(snapshot)) + " |");
                    builder.AppendLine("| Baseline learning | " + (snapshot.BaselineLearningMode ? "On" : "Off") + " |");
                    builder.AppendLine("| Automation-context alerts | " + metrics.AgentContext.ToString(CultureInfo.InvariantCulture) + " |");
                    builder.AppendLine("| Maintenance-context alerts | " + metrics.MaintenanceContext.ToString(CultureInfo.InvariantCulture) + " |");
                    builder.AppendLine();
                }

                if (DailyReportSectionEnabled("SignalSummary"))
                {
                    List<DailyAlertRecord> actionableAlerts = ActionableAlerts(alerts);
                    builder.AppendLine("## Actionable Signal Summary");
                    AppendBucketTable(builder, "Severity", BuildAlertBuckets(actionableAlerts, "severity"), config.DailyReportBucketRows);
                    builder.AppendLine();
                    AppendBucketTable(builder, "Top Categories", BuildAlertBuckets(actionableAlerts, "category"), config.DailyReportBucketRows);
                    builder.AppendLine();
                    AppendBucketTable(builder, "Top Rules", BuildAlertBuckets(actionableAlerts, "rule"), config.DailyReportBucketRows);
                    builder.AppendLine();
                }

                if (DailyReportSectionEnabled("FalsePositiveContext"))
                {
                    builder.AppendLine("## False Positive Context");
                    AppendFalsePositiveContext(builder, snapshot, metrics);
                    builder.AppendLine();
                }

                if (DailyReportSectionEnabled("HighSignalDetails"))
                {
                    builder.AppendLine("## High-Signal Details");
                    AppendHighSignal(builder, alerts, config.DailyReportHighSignalRows);
                    builder.AppendLine();
                }

                if (DailyReportSectionEnabled("AutomationActivity"))
                {
                    builder.AppendLine("## Automation Activity");
                    AppendAgentActivity(builder, agentActivities);
                }
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
            builder.AppendLine("LastCleanStopUtc: " + UtcTimestamp.Format(snapshot.LastCleanStopUtc));
            builder.AppendLine("BaselineLearningMode: " + snapshot.BaselineLearningMode);
            builder.AppendLine();

            builder.AppendLine("[alert_volume]");
            builder.AppendLine("WindowAlerts: " + alerts.Count.ToString(CultureInfo.InvariantCulture));
            builder.AppendLine("ActionableCriticalAlerts: " + metrics.CriticalCount.ToString(CultureInfo.InvariantCulture));
            builder.AppendLine("ActionableHighAlerts: " + metrics.HighCount.ToString(CultureInfo.InvariantCulture));
            builder.AppendLine("ActionableMediumAlerts: " + metrics.MediumCount.ToString(CultureInfo.InvariantCulture));
            builder.AppendLine("ActionableLowAlerts: " + metrics.LowCount.ToString(CultureInfo.InvariantCulture));
            builder.AppendLine("LocalCriticalAlerts: " + metrics.LocalCriticalCount.ToString(CultureInfo.InvariantCulture));
            builder.AppendLine("LocalHighAlerts: " + metrics.LocalHighCount.ToString(CultureInfo.InvariantCulture));
            builder.AppendLine("PolicySuppressedAlerts: " + metrics.PolicySuppressedCount.ToString(CultureInfo.InvariantCulture));
            builder.AppendLine("PolicySuppressedCriticalAlerts: " + metrics.PolicySuppressedCriticalCount.ToString(CultureInfo.InvariantCulture));
            builder.AppendLine("PolicySuppressedHighAlerts: " + metrics.PolicySuppressedHighCount.ToString(CultureInfo.InvariantCulture));
            builder.AppendLine("ActionableHighSignalAlerts: " + metrics.HighSignalCount.ToString(CultureInfo.InvariantCulture));
            builder.AppendLine("PolicySuppressedHighSignalAlerts: " + metrics.PolicySuppressedHighSignalCount.ToString(CultureInfo.InvariantCulture));
            builder.AppendLine("ExternalQualifiedBeforeRateLimits: " + metrics.ExternalQualified.ToString(CultureInfo.InvariantCulture));
            builder.AppendLine("MaintenanceContext: " + metrics.MaintenanceContext.ToString(CultureInfo.InvariantCulture));
            builder.AppendLine("AgentContext: " + metrics.AgentContext.ToString(CultureInfo.InvariantCulture));
            builder.AppendLine("HighestScore: " + metrics.HighestScore.ToString(CultureInfo.InvariantCulture));
            List<DailyAlertRecord> actionable = ActionableAlerts(alerts);
            AppendBuckets(builder, "Severity", BuildAlertBuckets(actionable, "severity"), 6);
            AppendBuckets(builder, "Category", BuildAlertBuckets(actionable, "category"), 8);
            AppendBuckets(builder, "Rule", BuildAlertBuckets(actionable, "rule"), 10);
            AppendBuckets(builder, "ProcessFamily", BuildAlertBuckets(actionable, "process"), 8);
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
            List<DailySignalSummary> highSignal = BuildHighSignalSummaries(alerts, 75, true);

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
                    " additional actionable high-signal alert group(s) omitted from this quick report.");
            }

            int suppressed = CountPolicySuppressedHighSignal(alerts, 75);
            if (suppressed > 0)
            {
                builder.AppendLine();
                builder.AppendLine(suppressed.ToString(CultureInfo.InvariantCulture) +
                    " policy-suppressed high-signal local record(s) were retained for audit and omitted from this priority table.");
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

            if (metrics.PolicySuppressedHighSignalCount > 0)
            {
                builder.AppendLine("| Policy-suppressed high-signal volume | " + TableCell(metrics.PolicySuppressedHighSignalCount.ToString(CultureInfo.InvariantCulture) +
                    " high-signal record(s) were retained locally but omitted from priority tables; spot-check the matching policy if that trust decision is stale.") + " |");
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
                if (alert.Score >= 90) metrics.LocalCriticalCount++;
                else if (alert.Score >= 75) metrics.LocalHighCount++;

                bool actionable = IsActionableForReport(alert);
                if (actionable)
                {
                    if (alert.Score >= 90) metrics.CriticalCount++;
                    else if (alert.Score >= 75) metrics.HighCount++;
                    else if (alert.Score >= 60) metrics.MediumCount++;
                    else metrics.LowCount++;
                }
                else
                {
                    metrics.PolicySuppressedCount++;
                    if (alert.Score >= 90) metrics.PolicySuppressedCriticalCount++;
                    else if (alert.Score >= 75) metrics.PolicySuppressedHighCount++;
                    if (IsHighSignalRecord(alert, 75)) metrics.PolicySuppressedHighSignalCount++;
                }

                if (WouldQualifyForExternal(alert)) metrics.ExternalQualified++;
                if (alert.MaintenanceContext) metrics.MaintenanceContext++;
                if (alert.AgentContext) metrics.AgentContext++;
            }

            metrics.HighSignalCount = BuildHighSignalList(snapshot.Alerts, 75, true).Count;
            return metrics;
        }

        private List<DailyAlertRecord> BuildHighSignalList(List<DailyAlertRecord> alerts, int minimumScore, bool actionableOnly)
        {
            List<DailyAlertRecord> highSignal = new List<DailyAlertRecord>();
            foreach (DailyAlertRecord alert in alerts)
            {
                if (actionableOnly && !IsActionableForReport(alert)) continue;
                if (IsHighSignalRecord(alert, minimumScore))
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

        private static bool IsHighSignalRecord(DailyAlertRecord alert, int minimumScore)
        {
            if (alert == null) return false;
            return alert.Score >= minimumScore ||
                (minimumScore <= 75 &&
                    AlertRuleTaxonomy.HasAnyPrefix(
                        alert.RuleId,
                        AlertRuleTaxonomy.PrefixAuthRemote,
                        AlertRuleTaxonomy.PrefixNetworkLan,
                        AlertRuleTaxonomy.PrefixPersistence,
                        AlertRuleTaxonomy.PrefixFile,
                        AlertRuleTaxonomy.PrefixRat));
        }

        private static int CountPolicySuppressedHighSignal(List<DailyAlertRecord> alerts, int minimumScore)
        {
            int count = 0;
            foreach (DailyAlertRecord alert in alerts)
            {
                if (!IsActionableForReport(alert) && IsHighSignalRecord(alert, minimumScore))
                {
                    count++;
                }
            }

            return count;
        }

        private static List<DailyAlertRecord> ActionableAlerts(List<DailyAlertRecord> alerts)
        {
            List<DailyAlertRecord> result = new List<DailyAlertRecord>();
            foreach (DailyAlertRecord alert in alerts)
            {
                if (IsActionableForReport(alert)) result.Add(alert);
            }

            return result;
        }

        private static bool IsActionableForReport(DailyAlertRecord alert)
        {
            if (alert == null) return false;
            return !alert.ExternalSuppressedByPolicy || alert.ExternalForcedByPolicy;
        }

        private List<DailySignalSummary> BuildHighSignalSummaries(List<DailyAlertRecord> alerts, int minimumScore, bool actionableOnly)
        {
            Dictionary<string, DailySignalSummary> summaries = new Dictionary<string, DailySignalSummary>(StringComparer.OrdinalIgnoreCase);
            foreach (DailyAlertRecord alert in BuildHighSignalList(alerts, minimumScore, actionableOnly))
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
            builder.AppendLine("| Policy-suppressed local evidence | " + PolicySuppressedSummary(metrics) +
                " | These records stay in JSONL/history but are left out of priority callouts unless the trust decision changes. |");
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
            builder.AppendLine("| Command categories | " + TableCell(JoinBucketSummary(BuildAgentBuckets(agentActivities, "command"), config.DailyReportAgentBucketRows)) + " |");
            builder.AppendLine("| Endpoint categories | " + TableCell(JoinBucketSummary(BuildAgentBuckets(agentActivities, "endpoint"), config.DailyReportAgentBucketRows)) + " |");
            builder.AppendLine("| File categories | " + TableCell(JoinBucketSummary(BuildAgentBuckets(agentActivities, "file"), config.DailyReportAgentBucketRows)) + " |");
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

            if (metrics.PolicySuppressedHighSignalCount > 0)
            {
                return "No confirmed compromise; policy-suppressed high-signal local evidence was retained but does not drive the primary review queue.";
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
            string reason = metrics.CriticalCount.ToString(CultureInfo.InvariantCulture) + " actionable critical-priority, " +
                metrics.HighCount.ToString(CultureInfo.InvariantCulture) + " actionable high-priority, " +
                metrics.PolicySuppressedHighSignalCount.ToString(CultureInfo.InvariantCulture) + " policy-suppressed high-signal retained locally, " +
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

            if (metrics.PolicySuppressedHighSignalCount > 0)
            {
                return "No priority action from tuned evidence; spot-check policy-suppressed context only if the trust decision changed.";
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

        private static string PolicySuppressedSummary(DailyReportMetrics metrics)
        {
            if (metrics.PolicySuppressedCount == 0) return "0";

            List<string> parts = new List<string>();
            parts.Add(metrics.PolicySuppressedCount.ToString(CultureInfo.InvariantCulture) + " retained locally");
            if (metrics.PolicySuppressedCriticalCount > 0)
            {
                parts.Add(metrics.PolicySuppressedCriticalCount.ToString(CultureInfo.InvariantCulture) + " critical");
            }

            if (metrics.PolicySuppressedHighCount > 0)
            {
                parts.Add(metrics.PolicySuppressedHighCount.ToString(CultureInfo.InvariantCulture) + " high");
            }

            if (metrics.PolicySuppressedHighSignalCount > 0)
            {
                parts.Add(metrics.PolicySuppressedHighSignalCount.ToString(CultureInfo.InvariantCulture) + " high-signal omitted from priority tables");
            }

            return String.Join("; ", parts.ToArray());
        }

        private static string ExplainAlert(DailyAlertRecord alert)
        {
            if (alert.ExternalSuppressedByPolicy && !alert.ExternalForcedByPolicy)
            {
                return "Policy-suppressed local evidence; retained for audit and omitted from priority review.";
            }

            if (AlertRuleTaxonomy.HasPrefix(alert.RuleId, AlertRuleTaxonomy.PrefixPowerShellEncoded)) return "Encoded or obfuscated PowerShell; review command origin and parent process.";
            if (AlertRuleTaxonomy.HasPrefix(alert.RuleId, AlertRuleTaxonomy.PrefixNetworkC2Beacon)) return "Beacon-like timing; confirm process and destination before assuming C2.";
            if (AlertRuleTaxonomy.HasPrefix(alert.RuleId, AlertRuleTaxonomy.PrefixRat)) return "RAT/LOLBin-style egress; verify command line and destination.";
            if (AlertRuleTaxonomy.HasPrefix(alert.RuleId, AlertRuleTaxonomy.PrefixAuthRemote)) return "Remote auth plus privilege context; verify account and source.";
            if (AlertRuleTaxonomy.HasPrefix(alert.RuleId, AlertRuleTaxonomy.PrefixNetworkLan)) return "LAN lateral/admin-port pattern; verify peer host and process.";
            if (AlertRuleTaxonomy.HasPrefix(alert.RuleId, AlertRuleTaxonomy.PrefixFile)) return "High-risk file write or drop-execute pattern; verify writer and path.";
            if (AlertRuleTaxonomy.HasPrefix(alert.RuleId, AlertRuleTaxonomy.PrefixPersistence)) return "Persistence change; verify expected administrative or software activity.";
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

        private bool DailyReportSectionEnabled(string section)
        {
            return config.DailyReportSections == null ||
                config.DailyReportSections.Count == 0 ||
                config.DailyReportSections.Contains(section);
        }

        private Dictionary<string, object> BuildMetricsObject(DailyReportMetrics metrics)
        {
            Dictionary<string, object> result = new Dictionary<string, object>(StringComparer.OrdinalIgnoreCase);
            result["window_alerts"] = metrics.WindowAlerts;
            result["actionable_critical_count"] = metrics.CriticalCount;
            result["actionable_high_count"] = metrics.HighCount;
            result["actionable_medium_count"] = metrics.MediumCount;
            result["actionable_low_count"] = metrics.LowCount;
            result["local_critical_count"] = metrics.LocalCriticalCount;
            result["local_high_count"] = metrics.LocalHighCount;
            result["policy_suppressed_count"] = metrics.PolicySuppressedCount;
            result["policy_suppressed_critical_count"] = metrics.PolicySuppressedCriticalCount;
            result["policy_suppressed_high_count"] = metrics.PolicySuppressedHighCount;
            result["policy_suppressed_high_signal_count"] = metrics.PolicySuppressedHighSignalCount;
            result["external_qualified_before_rate_limits"] = metrics.ExternalQualified;
            result["maintenance_context"] = metrics.MaintenanceContext;
            result["agent_context"] = metrics.AgentContext;
            result["highest_score"] = metrics.HighestScore;
            result["high_signal_count"] = metrics.HighSignalCount;
            return result;
        }

        private Dictionary<string, object> BuildHealthObject(DailyReportSnapshot snapshot)
        {
            Dictionary<string, object> result = new Dictionary<string, object>(StringComparer.OrdinalIgnoreCase);
            result["current_run_uptime_hours"] = snapshot.CurrentRunUptimeHours.ToString("0.00", CultureInfo.InvariantCulture);
            result["current_run_polls"] = snapshot.CurrentRunPolls;
            result["current_run_alerts"] = snapshot.CurrentRunAlerts;
            result["current_run_poll_failures"] = snapshot.CurrentRunPollFailures;
            result["total_polls"] = snapshot.TotalPolls;
            result["total_alerts"] = snapshot.TotalAlerts;
            result["total_poll_failures"] = snapshot.TotalPollFailures;
            result["external_send_failures"] = snapshot.ExternalSendFailures;
            result["last_clean_stop_utc"] = UtcTimestamp.Format(snapshot.LastCleanStopUtc);
            result["baseline_learning_mode"] = snapshot.BaselineLearningMode;
            result["read"] = BuildHealthRead(snapshot);
            return result;
        }

        private static Dictionary<string, object> BuildHostIdentityObject(HostIdentitySnapshot host)
        {
            Dictionary<string, object> result = new Dictionary<string, object>(StringComparer.OrdinalIgnoreCase);
            if (host == null)
            {
                result["machine_name"] = "";
                result["dns_host_name"] = "";
                result["local_ip_addresses"] = new List<string>();
                return result;
            }

            result["machine_name"] = host.MachineName;
            result["dns_host_name"] = host.DnsHostName;
            result["local_ip_addresses"] = new List<string>(host.LocalIpAddresses);
            return result;
        }

        private static string HostMachineText(HostIdentitySnapshot host)
        {
            if (host == null) return "unknown";
            if (!String.IsNullOrWhiteSpace(host.DnsHostName) &&
                !host.DnsHostName.Equals(host.DisplayName, StringComparison.OrdinalIgnoreCase))
            {
                return host.DisplayName + " (" + host.DnsHostName + ")";
            }

            return host.DisplayName;
        }

        private static string HostIpText(HostIdentitySnapshot host)
        {
            return host == null ? "unavailable" : host.LocalIpAddressSummary;
        }

        private static List<Dictionary<string, object>> BuildBucketObjects(List<DailyReportBucket> buckets, int limit)
        {
            List<Dictionary<string, object>> result = new List<Dictionary<string, object>>();
            int count = Math.Min(limit, buckets.Count);
            for (int index = 0; index < count; index++)
            {
                DailyReportBucket bucket = buckets[index];
                Dictionary<string, object> item = new Dictionary<string, object>(StringComparer.OrdinalIgnoreCase);
                item["name"] = bucket.Name;
                item["count"] = bucket.Count;
                item["max_score"] = bucket.MaxScore;
                item["maintenance_context"] = bucket.MaintenanceContext;
                item["agent_context"] = bucket.AgentContext;
                result.Add(item);
            }

            return result;
        }

        private static List<Dictionary<string, object>> BuildSignalObjects(List<DailySignalSummary> signals, int limit)
        {
            List<Dictionary<string, object>> result = new List<Dictionary<string, object>>();
            int count = Math.Min(limit, signals.Count);
            for (int index = 0; index < count; index++)
            {
                DailySignalSummary signal = signals[index];
                Dictionary<string, object> item = new Dictionary<string, object>(StringComparer.OrdinalIgnoreCase);
                item["latest_utc"] = UtcTimestamp.Format(signal.LatestTimestampUtc);
                item["rule_id"] = signal.RuleId;
                item["title"] = signal.Title;
                item["count"] = signal.Count;
                item["max_score"] = signal.MaxScore;
                item["process_summary"] = ProcessSummary(signal);
                item["assessment"] = ExplainAlert(signal.SampleAlert);
                result.Add(item);
            }

            return result;
        }

        private Dictionary<string, object> BuildAgentActivityObject(List<DailyAgentActivityRecord> agentActivities)
        {
            Dictionary<string, object> result = new Dictionary<string, object>(StringComparer.OrdinalIgnoreCase);
            result["records"] = agentActivities.Count;
            result["command_categories"] = BuildBucketObjects(BuildAgentBuckets(agentActivities, "command"), config.DailyReportAgentBucketRows);
            result["endpoint_categories"] = BuildBucketObjects(BuildAgentBuckets(agentActivities, "endpoint"), config.DailyReportAgentBucketRows);
            result["file_categories"] = BuildBucketObjects(BuildAgentBuckets(agentActivities, "file"), config.DailyReportAgentBucketRows);
            return result;
        }

        private Dictionary<string, object> BuildAiObject(AiAnalysisResult aiResult, string aiStatus)
        {
            Dictionary<string, object> result = new Dictionary<string, object>(StringComparer.OrdinalIgnoreCase);
            result["status"] = TextFormatting.EmptyIfNull(aiStatus);
            result["scope"] = "secondary_redacted_aggregate_review_only";
            if (aiResult != null)
            {
                result["providers"] = TextFormatting.EmptyIfNull(aiResult.ProviderName);
                result["flagged_for_review"] = aiResult.Alertable;
                result["cautious_score"] = aiResult.Score;
                result["read"] = TextFormatting.EmptyIfNull(aiResult.Title);
                result["summary"] = TextFormatting.EmptyIfNull(aiResult.Summary);
                result["suggested_action"] = TextFormatting.EmptyIfNull(aiResult.RecommendedAction);
                result["provider_results"] = BuildAiProviderObjects(aiResult);
            }

            return result;
        }

        private List<Dictionary<string, object>> BuildAiProviderObjects(AiAnalysisResult aiResult)
        {
            List<Dictionary<string, object>> results = new List<Dictionary<string, object>>();
            if (aiResult == null) return results;

            foreach (AiProviderAnalysisOutcome outcome in aiResult.ProviderOutcomes)
            {
                Dictionary<string, object> item = new Dictionary<string, object>(StringComparer.OrdinalIgnoreCase);
                item["provider"] = TextFormatting.EmptyIfNull(outcome.ProviderName);
                item["status"] = TextFormatting.EmptyIfNull(outcome.Status);
                item["flagged_for_review"] = outcome.Alertable;
                item["cautious_score"] = outcome.Score;
                item["read"] = TextFormatting.EmptyIfNull(outcome.Title);
                item["summary"] = TextFormatting.EmptyIfNull(outcome.Summary);
                item["suggested_action"] = TextFormatting.EmptyIfNull(outcome.RecommendedAction);
                item["error"] = TextFormatting.EmptyIfNull(outcome.Error);
                results.Add(item);
            }

            return results;
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
                if (!UtcTimestamp.TryParse(JsonFields.ReadString(parsed, "timestamp_utc"), out timestampUtc)) return null;

                DailyAlertRecord record = new DailyAlertRecord();
                record.TimestampUtc = timestampUtc;
                record.RuleId = TextFormatting.UnknownIfBlank(JsonFields.ReadString(parsed, "rule_id"));
                record.Category = TextFormatting.UnknownIfBlank(JsonFields.ReadString(parsed, "category"));
                if (record.Category.Equals("unknown", StringComparison.OrdinalIgnoreCase))
                {
                    record.Category = AlertRuleCatalog.CategoryFor(record.RuleId);
                }

                record.Severity = TextFormatting.UnknownIfBlank(JsonFields.ReadString(parsed, "severity"));
                record.Score = JsonFields.ReadInt(parsed, "score");
                record.Title = SanitizeText(JsonFields.ReadString(parsed, "title"));
                record.MaintenanceContext = JsonFields.ReadBool(parsed, "maintenance_context");
                record.ExternalSuppressedByPolicy = JsonFields.ReadBool(parsed, "external_suppressed_by_policy");
                record.ExternalForcedByPolicy = JsonFields.ReadBool(parsed, "external_forced_by_policy");
                record.ProcessFamily = ProcessFamily(JsonFields.ReadString(parsed, "entity"));
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
                if (!UtcTimestamp.TryParse(JsonFields.ReadString(parsed, "timestamp_utc"), out timestampUtc)) return null;

                DailyAgentActivityRecord record = new DailyAgentActivityRecord();
                record.TimestampUtc = timestampUtc;
                record.RuleId = TextFormatting.UnknownIfBlank(JsonFields.ReadString(parsed, "rule_id"));
                record.Score = JsonFields.ReadInt(parsed, "score");
                record.CommandCategory = TextFormatting.UnknownIfBlank(JsonFields.ReadString(parsed, "command_category"));
                record.EndpointCategory = TextFormatting.UnknownIfBlank(JsonFields.ReadString(parsed, "endpoint_category"));
                record.FileCategory = TextFormatting.UnknownIfBlank(JsonFields.ReadString(parsed, "file_category"));
                record.ProcessFamily = TextFormatting.UnknownIfBlank(JsonFields.ReadString(parsed, "process_family"));
                record.MaintenanceContext = JsonFields.ReadBool(parsed, "maintenance_context");
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

            return SortBuckets(buckets, field);
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

            return SortBuckets(buckets, field);
        }

        private static List<DailyReportBucket> SortBuckets(Dictionary<string, DailyReportBucket> buckets, string field)
        {
            List<DailyReportBucket> result = new List<DailyReportBucket>(buckets.Values);
            result.Sort(delegate(DailyReportBucket left, DailyReportBucket right)
            {
                if (field.Equals("severity", StringComparison.OrdinalIgnoreCase))
                {
                    int severityComparison = SeverityRank(right.Name).CompareTo(SeverityRank(left.Name));
                    if (severityComparison != 0) return severityComparison;
                }

                int scoreComparison = right.MaxScore.CompareTo(left.MaxScore);
                if (scoreComparison != 0) return scoreComparison;
                int countComparison = right.Count.CompareTo(left.Count);
                if (countComparison != 0) return countComparison;
                return String.Compare(left.Name, right.Name, StringComparison.OrdinalIgnoreCase);
            });
            return result;
        }

        private static int SeverityRank(string severity)
        {
            if (severity.Equals("critical", StringComparison.OrdinalIgnoreCase)) return 4;
            if (severity.Equals("high", StringComparison.OrdinalIgnoreCase)) return 3;
            if (severity.Equals("medium", StringComparison.OrdinalIgnoreCase)) return 2;
            if (severity.Equals("low", StringComparison.OrdinalIgnoreCase)) return 1;
            return 0;
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
            if (record == null) return false;

            Alert alert = new Alert();
            alert.RuleId = record.RuleId;
            alert.Category = record.Category;
            alert.Score = record.Score;
            alert.Title = record.Title;
            alert.MaintenanceContext = record.MaintenanceContext;
            alert.ExternalSuppressedByPolicy = record.ExternalSuppressedByPolicy;
            alert.ExternalForcedByPolicy = record.ExternalForcedByPolicy;

            return ExternalAlertEligibility.WouldQualifyBeforeRateLimits(
                config,
                alert,
                false,
                false);
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
            if (config.AIAnalysisExcludedRuleIds.Contains(ruleId)) return true;
            return AlertRuleTaxonomy.IsDailySummaryRule(ruleId);
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
            string value = AlertEntityTokens.FirstNonEmpty(
                AlertEntityTokens.Get(entity, "process"),
                AlertEntityTokens.Get(entity, "image"),
                AlertEntityTokens.Get(entity, "process_path"),
                AlertEntityTokens.Get(entity, "host_application"));
            if (String.IsNullOrWhiteSpace(value)) return "unknown";

            return SanitizeProcessToken(AlertEntityTokens.FileNameOrValue(value));
        }

        private static bool HasAgentContext(IDictionary parsed)
        {
            if (TextFormatting.ContainsIgnoreCase(JsonFields.ReadString(parsed, "body"), "AgentContext: involved")) return true;
            if (TextFormatting.ContainsIgnoreCase(JsonFields.ReadString(parsed, "entity"), "agent_context=involved")) return true;
            return TextFormatting.ContainsIgnoreCase(JsonFields.ReadString(parsed, "why"), "agent-") ||
                TextFormatting.ContainsIgnoreCase(JsonFields.ReadString(parsed, "why"), "unattended-agent");
        }

        private static string Limit(string value, int maxChars)
        {
            if (String.IsNullOrWhiteSpace(value) || maxChars <= 0 || value.Length <= maxChars) return value;
            return value.Substring(value.Length - maxChars);
        }

        private static string TableCell(string value)
        {
            string result = TextFormatting.EmptyIfNull(value)
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
            return SensitiveTextRedactor.RedactForDailyReport(value);
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
        public HostIdentitySnapshot HostIdentity;
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
        public bool ExternalSuppressedByPolicy;
        public bool ExternalForcedByPolicy;
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
        public int LocalCriticalCount;
        public int LocalHighCount;
        public int PolicySuppressedCount;
        public int PolicySuppressedCriticalCount;
        public int PolicySuppressedHighCount;
        public int PolicySuppressedHighSignalCount;
        public int ExternalQualified;
        public int MaintenanceContext;
        public int AgentContext;
        public int HighestScore;
        public int HighSignalCount;
    }
}
