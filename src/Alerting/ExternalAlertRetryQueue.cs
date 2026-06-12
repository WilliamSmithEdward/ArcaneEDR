using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Net;
using System.Text;

namespace ArcaneEDR
{
    internal delegate bool ExternalAlertSendAttempt(Alert alert, out string failureReason);

    internal sealed class ExternalAlertRetryQueue
    {
        private readonly MonitorConfig config;
        private readonly FileLogger logger;
        private readonly List<ExternalAlertRetryItem> items = new List<ExternalAlertRetryItem>();

        public ExternalAlertRetryQueue(MonitorConfig config, FileLogger logger)
        {
            this.config = config;
            this.logger = logger;
            Load();
        }

        public void Enqueue(Alert alert, string failureReason)
        {
            if (!config.ExternalAlertRetryEnabled) return;
            if (config.ExternalAlertRetryMaxAttempts <= 1) return;

            if (Contains(alert))
            {
                return;
            }

            if (items.Count >= config.ExternalAlertRetryMaxQueued)
            {
                logger.Warn("External alert retry queue full; dropping retry for " + alert.RuleId + ".");
                return;
            }

            ExternalAlertRetryItem item = new ExternalAlertRetryItem();
            item.Alert = Clone(alert);
            item.Attempts = 1;
            item.NextAttemptUtc = DateTime.UtcNow.AddSeconds(NextDelaySeconds(1));
            item.LastFailureReason = failureReason ?? "";
            items.Add(item);
            Save();

            logger.Warn("Queued external alert retry for " + alert.RuleId + " after send failure. NextAttemptUtc=" + UtcTimestamp.Format(item.NextAttemptUtc));
        }

        public void RetryDue(ExternalAlertSendAttempt sendAttempt)
        {
            if (!config.ExternalAlertRetryEnabled) return;
            if (items.Count == 0) return;

            DateTime now = DateTime.UtcNow;
            int retried = 0;
            bool changed = false;

            for (int index = 0; index < items.Count && retried < config.ExternalAlertRetryMaxPerPoll;)
            {
                ExternalAlertRetryItem item = items[index];
                if (item.NextAttemptUtc > now)
                {
                    index++;
                    continue;
                }

                retried++;
                string failureReason;
                if (sendAttempt(item.Alert, out failureReason))
                {
                    logger.Info("Delivered queued external alert for " + item.Alert.RuleId + " after " + item.Attempts.ToString(CultureInfo.InvariantCulture) + " failed attempt(s).");
                    items.RemoveAt(index);
                    changed = true;
                    continue;
                }

                if (String.IsNullOrWhiteSpace(failureReason))
                {
                    item.NextAttemptUtc = now.AddSeconds(NextDelaySeconds(item.Attempts));
                    changed = true;
                    index++;
                    logger.Info("Deferred queued external alert for " + item.Alert.RuleId + " because sink routing did not accept it.");
                    continue;
                }

                item.Attempts++;
                item.LastFailureReason = failureReason ?? "";
                if (item.Attempts >= config.ExternalAlertRetryMaxAttempts)
                {
                    logger.Error("Dropping queued external alert for " + item.Alert.RuleId + " after " + item.Attempts.ToString(CultureInfo.InvariantCulture) + " failed attempts. LastFailure=" + item.LastFailureReason);
                    items.RemoveAt(index);
                    changed = true;
                    continue;
                }

                item.NextAttemptUtc = now.AddSeconds(NextDelaySeconds(item.Attempts));
                changed = true;
                index++;
            }

            if (changed)
            {
                Save();
            }
        }

        private bool Contains(Alert alert)
        {
            foreach (ExternalAlertRetryItem item in items)
            {
                if (item.Alert.RuleId == alert.RuleId &&
                    item.Alert.CooldownKey == alert.CooldownKey &&
                    item.Alert.Title == alert.Title)
                {
                    return true;
                }
            }

            return false;
        }

        private int NextDelaySeconds(int attempts)
        {
            int baseSeconds = Math.Max(1, config.ExternalAlertRetryIntervalSeconds);
            int capSeconds = Math.Max(baseSeconds, config.ExternalAlertRetryMaxIntervalSeconds);
            int exponent = Math.Max(0, Math.Min(attempts - 1, 10));
            double delay = baseSeconds * Math.Pow(2.0, exponent);
            if (delay > capSeconds) delay = capSeconds;
            return (int)delay;
        }

        private void Load()
        {
            try
            {
                if (!File.Exists(config.ExternalAlertRetryQueueFile)) return;

                foreach (string line in File.ReadAllLines(config.ExternalAlertRetryQueueFile))
                {
                    ExternalAlertRetryItem item;
                    if (TryParse(line, out item))
                    {
                        items.Add(item);
                    }
                }
            }
            catch (Exception ex)
            {
                logger.Warn("External alert retry queue could not be loaded: " + ex.Message);
            }
        }

        private void Save()
        {
            try
            {
                string directory = Path.GetDirectoryName(config.ExternalAlertRetryQueueFile);
                if (!String.IsNullOrWhiteSpace(directory))
                {
                    Directory.CreateDirectory(directory);
                }

                List<string> lines = new List<string>();
                foreach (ExternalAlertRetryItem item in items)
                {
                    lines.Add(Serialize(item));
                }

                File.WriteAllLines(config.ExternalAlertRetryQueueFile, lines.ToArray());
            }
            catch (Exception ex)
            {
                logger.Warn("External alert retry queue could not be saved: " + ex.Message);
            }
        }

        private static Alert Clone(Alert source)
        {
            return new Alert
            {
                RuleId = source.RuleId,
                Title = source.Title,
                Score = source.Score,
                Severity = source.Severity,
                Category = source.Category,
                MaintenanceContext = source.MaintenanceContext,
                Body = source.Body,
                Recommendation = source.Recommendation,
                EntitySummary = source.EntitySummary,
                Why = source.Why == null ? new List<string>() : new List<string>(source.Why),
                CooldownKey = source.CooldownKey,
                TimestampUtc = source.TimestampUtc,
                ResponseProcessId = source.ResponseProcessId,
                ResponseRemoteAddress = source.ResponseRemoteAddress,
                AlertId = source.EnsureAlertId(),
                ExternalNotificationSent = source.ExternalNotificationSent,
                ExternalNotificationStatus = source.ExternalNotificationStatus,
                ExternalNotificationReason = source.ExternalNotificationReason,
                ExternalSuppressedByPolicy = source.ExternalSuppressedByPolicy,
                ExternalForcedByPolicy = source.ExternalForcedByPolicy,
                PolicyContext = source.PolicyContext
            };
        }

        private static string Serialize(ExternalAlertRetryItem item)
        {
            Alert alert = item.Alert;
            string remoteAddress = alert.ResponseRemoteAddress == null ? "" : alert.ResponseRemoteAddress.ToString();
            string[] fields = new string[]
            {
                UtcTimestamp.Format(item.NextAttemptUtc),
                item.Attempts.ToString(CultureInfo.InvariantCulture),
                Encode(alert.RuleId),
                Encode(alert.Title),
                alert.Score.ToString(CultureInfo.InvariantCulture),
                Encode(alert.Severity),
                Encode(alert.Body),
                Encode(alert.Recommendation),
                Encode(alert.EntitySummary),
                Encode(alert.CooldownKey),
                UtcTimestamp.Format(alert.TimestampUtc),
                alert.ResponseProcessId.ToString(CultureInfo.InvariantCulture),
                Encode(remoteAddress),
                Encode(item.LastFailureReason),
                Encode(AlertWhyText.Join(alert, "\n")),
                Encode(AlertRulePolicy.AlertCategory(alert)),
                alert.MaintenanceContext ? "true" : "false",
                Encode(alert.SystemLocalTime),
                Encode(alert.SystemTimeZoneId),
                Encode(alert.SystemUtcOffset),
                Encode(alert.EnsureAlertId()),
                alert.ExternalNotificationSent ? "true" : "false",
                Encode(alert.ExternalNotificationStatus),
                Encode(alert.ExternalNotificationReason),
                alert.ExternalSuppressedByPolicy ? "true" : "false",
                alert.ExternalForcedByPolicy ? "true" : "false",
                Encode(alert.PolicyContext)
            };

            return String.Join("\t", fields);
        }

        private static bool TryParse(string line, out ExternalAlertRetryItem item)
        {
            item = null;
            if (String.IsNullOrWhiteSpace(line)) return false;

            string[] fields = line.Split('\t');
            if (fields.Length < 14) return false;

            DateTime nextAttempt;
            DateTime timestamp;
            int attempts;
            int score;
            int processId;

            if (!DateTime.TryParse(fields[0], out nextAttempt)) return false;
            if (!Int32.TryParse(fields[1], out attempts)) return false;
            if (!Int32.TryParse(fields[4], out score)) return false;
            if (!DateTime.TryParse(fields[10], out timestamp)) return false;
            if (!Int32.TryParse(fields[11], out processId)) processId = 0;

            IPAddress remoteAddress = null;
            string remoteText = Decode(fields[12]);
            IPAddress parsedRemote;
            if (IPAddress.TryParse(remoteText, out parsedRemote))
            {
                remoteAddress = parsedRemote;
            }

            Alert alert = new Alert
            {
                RuleId = Decode(fields[2]),
                Title = Decode(fields[3]),
                Score = score,
                Severity = Decode(fields[5]),
                Category = fields.Length > 15 ? Decode(fields[15]) : AlertRuleCatalog.CategoryFor(Decode(fields[2])),
                MaintenanceContext = fields.Length > 16 && fields[16].Equals("true", StringComparison.OrdinalIgnoreCase),
                Body = Decode(fields[6]),
                Recommendation = Decode(fields[7]),
                EntitySummary = Decode(fields[8]),
                CooldownKey = Decode(fields[9]),
                TimestampUtc = timestamp.ToUniversalTime(),
                ResponseProcessId = processId,
                ResponseRemoteAddress = remoteAddress,
                AlertId = fields.Length > 20 ? Decode(fields[20]) : "",
                ExternalNotificationSent = fields.Length > 21 && fields[21].Equals("true", StringComparison.OrdinalIgnoreCase),
                ExternalNotificationStatus = fields.Length > 22 ? Decode(fields[22]) : "",
                ExternalNotificationReason = fields.Length > 23 ? Decode(fields[23]) : "",
                ExternalSuppressedByPolicy = fields.Length > 24 && fields[24].Equals("true", StringComparison.OrdinalIgnoreCase),
                ExternalForcedByPolicy = fields.Length > 25 && fields[25].Equals("true", StringComparison.OrdinalIgnoreCase),
                PolicyContext = fields.Length > 26 ? Decode(fields[26]) : ""
            };

            if (fields.Length > 14)
            {
                foreach (string reason in Decode(fields[14]).Split('\n'))
                {
                    alert.AddWhy(reason);
                }
            }

            item = new ExternalAlertRetryItem();
            item.Alert = alert;
            item.Attempts = attempts;
            item.NextAttemptUtc = nextAttempt.ToUniversalTime();
            item.LastFailureReason = Decode(fields[13]);
            return true;
        }

        private static string Encode(string value)
        {
            return Convert.ToBase64String(Encoding.UTF8.GetBytes(value ?? ""));
        }

        private static string Decode(string value)
        {
            try
            {
                return Encoding.UTF8.GetString(Convert.FromBase64String(value));
            }
            catch
            {
                return "";
            }
        }

    }

    internal sealed class ExternalAlertRetryItem
    {
        public Alert Alert;
        public int Attempts;
        public DateTime NextAttemptUtc;
        public string LastFailureReason;
    }
}
