using System;
using System.Collections.Generic;
using System.Globalization;
using System.Net;

namespace ArcaneEDR
{
    internal sealed class Alert
    {
        public string RuleId;
        public string Title;
        public int Score;
        public string Severity;
        public string Category;
        public string Body;
        public string Recommendation;
        public string EntitySummary;
        public string CooldownKey;
        public List<string> Why = new List<string>();
        public DateTime TimestampUtc;
        public int ResponseProcessId;
        public IPAddress ResponseRemoteAddress;

        public static Alert Create(string ruleId, string title, int score, string body, string recommendation, string cooldownKey)
        {
            return new Alert
            {
                RuleId = ruleId,
                Title = title,
                Score = score,
                Severity = SeverityFromScore(score),
                Body = body,
                Recommendation = recommendation,
                EntitySummary = "n/a",
                CooldownKey = cooldownKey,
                TimestampUtc = DateTime.UtcNow,
                ResponseProcessId = 0,
                ResponseRemoteAddress = null
            };
        }

        public static Alert FromEndpoint(string ruleId, string title, int score, string body, string recommendation, NetworkEndpoint endpoint)
        {
            return new Alert
            {
                RuleId = ruleId,
                Title = title,
                Score = score,
                Severity = SeverityFromScore(score),
                Body = body + Environment.NewLine + "Endpoint: " + endpoint,
                Recommendation = recommendation,
                EntitySummary = endpoint.EntitySummary,
                CooldownKey = ruleId + "|" + endpoint.ProcessId.ToString(CultureInfo.InvariantCulture) + "|" + endpoint.LocalPort.ToString(CultureInfo.InvariantCulture) + "|" + endpoint.RemoteAddress + "|" + endpoint.RemotePort.ToString(CultureInfo.InvariantCulture),
                TimestampUtc = DateTime.UtcNow,
                ResponseProcessId = endpoint.ProcessId,
                ResponseRemoteAddress = endpoint.RemoteAddress
            };
        }

        public static Alert FromDnsQuery(string ruleId, string title, int score, string body, string recommendation, DnsQueryEvent dns)
        {
            return new Alert
            {
                RuleId = ruleId,
                Title = title,
                Score = score,
                Severity = SeverityFromScore(score),
                Body = body + Environment.NewLine + "DNS: " + dns.EntitySummary,
                Recommendation = recommendation,
                EntitySummary = dns.EntitySummary,
                CooldownKey = ruleId + "|" + dns.CooldownKey,
                TimestampUtc = DateTime.UtcNow,
                ResponseProcessId = dns.ProcessId,
                ResponseRemoteAddress = null
            };
        }

        public static Alert FromProcessEvent(string ruleId, string title, int score, string body, string recommendation, SysmonProcessEvent process)
        {
            return new Alert
            {
                RuleId = ruleId,
                Title = title,
                Score = score,
                Severity = SeverityFromScore(score),
                Body = body + Environment.NewLine + "Process: " + process.EntitySummary,
                Recommendation = recommendation,
                EntitySummary = process.EntitySummary,
                CooldownKey = ruleId + "|" + process.RecordId.ToString(CultureInfo.InvariantCulture) + "|" + process.ProcessId.ToString(CultureInfo.InvariantCulture),
                TimestampUtc = DateTime.UtcNow,
                ResponseProcessId = process.ProcessId,
                ResponseRemoteAddress = null
            };
        }

        public static Alert FromPowerShellEvent(string ruleId, string title, int score, string body, string recommendation, PowerShellEvent ev)
        {
            return new Alert
            {
                RuleId = ruleId,
                Title = title,
                Score = score,
                Severity = SeverityFromScore(score),
                Body = body + Environment.NewLine + "PowerShell: " + ev.EntitySummary,
                Recommendation = recommendation,
                EntitySummary = ev.EntitySummary,
                CooldownKey = ruleId + "|" + ev.CooldownKey,
                TimestampUtc = DateTime.UtcNow,
                ResponseProcessId = 0,
                ResponseRemoteAddress = null
            };
        }

        public static Alert FromWindowsEvent(string ruleId, string title, int score, string body, string recommendation, WindowsAuditEvent ev)
        {
            return new Alert
            {
                RuleId = ruleId,
                Title = title,
                Score = score,
                Severity = SeverityFromScore(score),
                Body = body + Environment.NewLine + "WindowsEvent: " + ev.EntitySummary,
                Recommendation = recommendation,
                EntitySummary = ev.EntitySummary,
                CooldownKey = ruleId + "|" + ev.CooldownKey,
                TimestampUtc = DateTime.UtcNow,
                ResponseProcessId = 0,
                ResponseRemoteAddress = null
            };
        }

        public static Alert FromPersistenceItem(string ruleId, string title, int score, string body, string recommendation, PersistenceItem item)
        {
            return new Alert
            {
                RuleId = ruleId,
                Title = title,
                Score = score,
                Severity = SeverityFromScore(score),
                Body = body + Environment.NewLine + "Persistence: " + item.EntitySummary,
                Recommendation = recommendation,
                EntitySummary = item.EntitySummary,
                CooldownKey = ruleId + "|" + item.Identity,
                TimestampUtc = DateTime.UtcNow,
                ResponseProcessId = 0,
                ResponseRemoteAddress = null
            };
        }

        public static Alert SystemAlert(string ruleId, string title, int score, string body, string recommendation)
        {
            return SystemAlert(ruleId, title, score, body, recommendation, "service=arcane-edr");
        }

        public static Alert SystemAlert(string ruleId, string title, int score, string body, string recommendation, string entitySummary)
        {
            return new Alert
            {
                RuleId = ruleId,
                Title = title,
                Score = score,
                Severity = SeverityFromScore(score),
                Body = body,
                Recommendation = recommendation,
                EntitySummary = entitySummary,
                CooldownKey = ruleId + "|" + title,
                TimestampUtc = DateTime.UtcNow,
                ResponseProcessId = 0,
                ResponseRemoteAddress = null
            };
        }

        public string ToJson()
        {
            return "{" +
                "\"timestamp_utc\":\"" + JsonEscape(TimestampUtc.ToString("yyyy-MM-ddTHH:mm:ssZ", CultureInfo.InvariantCulture)) + "\"," +
                "\"rule_id\":\"" + JsonEscape(RuleId) + "\"," +
                "\"category\":\"" + JsonEscape(Category) + "\"," +
                "\"severity\":\"" + JsonEscape(Severity) + "\"," +
                "\"score\":" + Score.ToString(CultureInfo.InvariantCulture) + "," +
                "\"title\":\"" + JsonEscape(Title) + "\"," +
                "\"why\":" + WhyToJson() + "," +
                "\"body\":\"" + JsonEscape(Body) + "\"," +
                "\"recommendation\":\"" + JsonEscape(Recommendation) + "\"," +
                "\"entity\":\"" + JsonEscape(EntitySummary) + "\"," +
                "\"response_process_id\":" + ResponseProcessId.ToString(CultureInfo.InvariantCulture) + "," +
                "\"response_remote_address\":\"" + JsonEscape(ResponseRemoteAddress == null ? "" : ResponseRemoteAddress.ToString()) + "\"" +
                "}";
        }

        public void AddWhy(string reason)
        {
            if (String.IsNullOrWhiteSpace(reason)) return;
            if (Why == null) Why = new List<string>();

            string normalized = reason.Trim();
            foreach (string existing in Why)
            {
                if (existing.Equals(normalized, StringComparison.OrdinalIgnoreCase)) return;
            }

            Why.Add(normalized);
        }

        private static string SeverityFromScore(int score)
        {
            if (score >= 90) return "critical";
            if (score >= 75) return "high";
            if (score >= 60) return "medium";
            return "low";
        }

        private string WhyToJson()
        {
            if (Why == null || Why.Count == 0) return "[]";

            List<string> encoded = new List<string>();
            foreach (string reason in Why)
            {
                encoded.Add("\"" + JsonEscape(reason) + "\"");
            }

            return "[" + String.Join(",", encoded.ToArray()) + "]";
        }

        private static string JsonEscape(string value)
        {
            if (value == null) return "";
            return value
                .Replace("\\", "\\\\")
                .Replace("\"", "\\\"")
                .Replace("\r", "\\r")
                .Replace("\n", "\\n");
        }
    }
}
