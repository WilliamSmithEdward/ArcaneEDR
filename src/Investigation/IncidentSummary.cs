using System;
using System.Collections.Generic;

namespace ArcaneEDR
{
    internal sealed class IncidentSummary
    {
        public string IncidentId;
        public string GroupKey;
        public string Host;
        public string Category;
        public string User;
        public string Process;
        public DateTime FirstSeenUtc = DateTime.MaxValue;
        public DateTime LastSeenUtc = DateTime.MinValue;
        public int AlertCount;
        public bool HasMaintenanceContext;
        public int MaxScore;
        public string Severity;
        public string LatestTitle;
        public string LatestRecommendation;
        public List<string> RuleIds = new List<string>();

        public void Apply(IncidentRecord record, DateTime observedUtc)
        {
            if (AlertCount == 0)
            {
                IncidentId = record.incident_id;
                GroupKey = record.group_key;
                Host = record.host;
                Category = record.category;
                User = record.user;
                Process = record.process;
            }

            AlertCount++;
            if (record.maintenance_context) HasMaintenanceContext = true;
            if (observedUtc < FirstSeenUtc) FirstSeenUtc = observedUtc;
            if (observedUtc >= LastSeenUtc)
            {
                LastSeenUtc = observedUtc;
                LatestTitle = record.title;
                LatestRecommendation = record.recommendation;
            }

            if (record.score > MaxScore)
            {
                MaxScore = record.score;
                Severity = record.severity;
            }

            AddRule(record.rule_id);
        }

        private void AddRule(string ruleId)
        {
            if (String.IsNullOrWhiteSpace(ruleId)) return;
            foreach (string existing in RuleIds)
            {
                if (existing.Equals(ruleId, StringComparison.OrdinalIgnoreCase)) return;
            }

            RuleIds.Add(ruleId);
        }
    }
}
