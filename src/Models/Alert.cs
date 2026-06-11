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
        public bool MaintenanceContext;
        public string Body;
        public string Recommendation;
        public string EntitySummary;
        public string CooldownKey;
        public List<string> Why = new List<string>();
        public DateTime TimestampUtc;
        public int ResponseProcessId;
        public IPAddress ResponseRemoteAddress;
        public bool ExternalSuppressedByPolicy;
        public bool ExternalForcedByPolicy;
        public string PolicyContext;

        public string SystemLocalTime
        {
            get { return FormatSystemLocalTime(TimestampUtc); }
        }

        public string SystemTimeZoneId
        {
            get { return LocalTimeZone().Id; }
        }

        public string SystemUtcOffset
        {
            get { return FormatSystemUtcOffset(TimestampUtc); }
        }

        public static Alert Create(string ruleId, string title, int score, string body, string recommendation, string cooldownKey)
        {
            return new Alert
            {
                RuleId = ruleId,
                Title = title,
                Score = score,
                Severity = AlertSeverity.FromScore(score),
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
                Severity = AlertSeverity.FromScore(score),
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
                Severity = AlertSeverity.FromScore(score),
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
                Severity = AlertSeverity.FromScore(score),
                Body = body + Environment.NewLine + "Process: " + process.EntitySummary,
                Recommendation = recommendation,
                EntitySummary = process.EntitySummary,
                CooldownKey = ruleId + "|" + process.RecordId.ToString(CultureInfo.InvariantCulture) + "|" + process.ProcessId.ToString(CultureInfo.InvariantCulture),
                TimestampUtc = DateTime.UtcNow,
                ResponseProcessId = process.ProcessId,
                ResponseRemoteAddress = null
            };
        }

        public static Alert FromFileEvent(string ruleId, string title, int score, string body, string recommendation, SysmonFileEvent ev)
        {
            return new Alert
            {
                RuleId = ruleId,
                Title = title,
                Score = score,
                Severity = AlertSeverity.FromScore(score),
                Body = body + Environment.NewLine + "FileEvent: " + ev.EntitySummary,
                Recommendation = recommendation,
                EntitySummary = ev.EntitySummary,
                CooldownKey = ruleId + "|" + ev.CooldownKey,
                TimestampUtc = DateTime.UtcNow,
                ResponseProcessId = ev.ProcessId,
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
                Severity = AlertSeverity.FromScore(score),
                Body = body + Environment.NewLine + "PowerShell: " + ev.EntitySummary,
                Recommendation = recommendation,
                EntitySummary = ev.EntitySummary,
                CooldownKey = ruleId + "|" + ev.CooldownKey,
                TimestampUtc = DateTime.UtcNow,
                ResponseProcessId = ev.ProcessId,
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
                Severity = AlertSeverity.FromScore(score),
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
                Severity = AlertSeverity.FromScore(score),
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
                Severity = AlertSeverity.FromScore(score),
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
                "\"timestamp_utc\":\"" + JsonFields.Escape(UtcTimestamp.Format(TimestampUtc)) + "\"," +
                "\"system_local_time\":\"" + JsonFields.Escape(SystemLocalTime) + "\"," +
                "\"system_time_zone\":\"" + JsonFields.Escape(SystemTimeZoneId) + "\"," +
                "\"system_utc_offset\":\"" + JsonFields.Escape(SystemUtcOffset) + "\"," +
                "\"rule_id\":\"" + JsonFields.Escape(RuleId) + "\"," +
                "\"category\":\"" + JsonFields.Escape(Category) + "\"," +
                "\"maintenance_context\":" + (MaintenanceContext ? "true" : "false") + "," +
                "\"severity\":\"" + JsonFields.Escape(Severity) + "\"," +
                "\"score\":" + Score.ToString(CultureInfo.InvariantCulture) + "," +
                "\"title\":\"" + JsonFields.Escape(Title) + "\"," +
                "\"why\":" + WhyToJson() + "," +
                "\"policy_context\":\"" + JsonFields.Escape(PolicyContext) + "\"," +
                "\"external_suppressed_by_policy\":" + (ExternalSuppressedByPolicy ? "true" : "false") + "," +
                "\"external_forced_by_policy\":" + (ExternalForcedByPolicy ? "true" : "false") + "," +
                "\"body\":\"" + JsonFields.Escape(Body) + "\"," +
                "\"recommendation\":\"" + JsonFields.Escape(Recommendation) + "\"," +
                "\"entity\":\"" + JsonFields.Escape(EntitySummary) + "\"," +
                "\"response_process_id\":" + ResponseProcessId.ToString(CultureInfo.InvariantCulture) + "," +
                "\"response_remote_address\":\"" + JsonFields.Escape(ResponseRemoteAddress == null ? "" : ResponseRemoteAddress.ToString()) + "\"" +
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

        public void AddPolicyContext(string context)
        {
            if (String.IsNullOrWhiteSpace(context)) return;

            string normalized = context.Trim();
            if (String.IsNullOrWhiteSpace(PolicyContext))
            {
                PolicyContext = normalized;
                return;
            }

            foreach (string existing in PolicyContext.Split(','))
            {
                if (existing.Trim().Equals(normalized, StringComparison.OrdinalIgnoreCase)) return;
            }

            PolicyContext = PolicyContext + "," + normalized;
        }

        public void SetScore(int score)
        {
            if (score < 0) score = 0;
            if (score > 100) score = 100;
            Score = score;
            Severity = AlertSeverity.FromScore(score);
        }

        private string WhyToJson()
        {
            if (Why == null || Why.Count == 0) return "[]";

            List<string> encoded = new List<string>();
            foreach (string reason in Why)
            {
                encoded.Add("\"" + JsonFields.Escape(reason) + "\"");
            }

            return "[" + String.Join(",", encoded.ToArray()) + "]";
        }

        private static string FormatSystemLocalTime(DateTime timestampUtc)
        {
            DateTime utc = NormalizeUtc(timestampUtc);
            TimeZoneInfo zone = LocalTimeZone();
            DateTime local = TimeZoneInfo.ConvertTimeFromUtc(utc, zone);
            TimeSpan offset = zone.GetUtcOffset(utc);
            DateTimeOffset localWithOffset = new DateTimeOffset(local, offset);
            return localWithOffset.ToString("yyyy-MM-ddTHH:mm:ss zzz", CultureInfo.InvariantCulture) +
                " (" + zone.Id + ")";
        }

        private static string FormatSystemUtcOffset(DateTime timestampUtc)
        {
            DateTime utc = NormalizeUtc(timestampUtc);
            TimeZoneInfo zone = LocalTimeZone();
            DateTime local = TimeZoneInfo.ConvertTimeFromUtc(utc, zone);
            TimeSpan offset = zone.GetUtcOffset(utc);
            DateTimeOffset localWithOffset = new DateTimeOffset(local, offset);
            return localWithOffset.ToString("zzz", CultureInfo.InvariantCulture);
        }

        private static DateTime NormalizeUtc(DateTime timestampUtc)
        {
            if (timestampUtc.Kind == DateTimeKind.Utc) return timestampUtc;
            return timestampUtc.ToUniversalTime();
        }

        private static TimeZoneInfo LocalTimeZone()
        {
            try
            {
                return TimeZoneInfo.Local;
            }
            catch
            {
                return TimeZoneInfo.Utc;
            }
        }

    }
}
