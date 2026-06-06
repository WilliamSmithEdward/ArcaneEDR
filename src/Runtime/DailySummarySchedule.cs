using System;
using System.Globalization;

namespace ArcaneEDR
{
    internal static class DailySummarySchedule
    {
        public static bool IsDue(MonitorConfig config, DateTime nowUtc, DateTime? lastSummaryUtc)
        {
            TimeSpan localTime;
            if (!TryParseTime(config.DailySummaryLocalTime, out localTime))
            {
                return IsIntervalDue(config, nowUtc, lastSummaryUtc);
            }

            TimeZoneInfo zone = ResolveTimeZone(config.DailySummaryTimeZoneId);
            DateTime nowLocal = TimeZoneInfo.ConvertTimeFromUtc(nowUtc, zone);
            DateTime scheduledLocal = nowLocal.Date.Add(localTime);

            if (nowLocal < scheduledLocal)
            {
                return false;
            }

            if (!lastSummaryUtc.HasValue)
            {
                return true;
            }

            DateTime lastLocal = TimeZoneInfo.ConvertTimeFromUtc(lastSummaryUtc.Value.ToUniversalTime(), zone);
            return lastLocal.Date < nowLocal.Date;
        }

        public static string Describe(MonitorConfig config)
        {
            TimeZoneInfo zone = ResolveTimeZone(config.DailySummaryTimeZoneId);
            return (String.IsNullOrWhiteSpace(config.DailySummaryLocalTime) ? "interval" : config.DailySummaryLocalTime) +
                " " + zone.Id;
        }

        private static bool IsIntervalDue(MonitorConfig config, DateTime nowUtc, DateTime? lastSummaryUtc)
        {
            if (!lastSummaryUtc.HasValue) return true;
            return (nowUtc - lastSummaryUtc.Value.ToUniversalTime()).TotalHours >= config.DailySummaryIntervalHours;
        }

        private static bool TryParseTime(string value, out TimeSpan time)
        {
            time = TimeSpan.Zero;
            if (String.IsNullOrWhiteSpace(value)) return false;

            DateTime parsedDate;
            if (DateTime.TryParseExact(value.Trim(), new[] { "H:mm", "HH:mm", "h:mm tt", "hh:mm tt" },
                CultureInfo.InvariantCulture, DateTimeStyles.None, out parsedDate))
            {
                time = parsedDate.TimeOfDay;
                return true;
            }

            TimeSpan parsedSpan;
            if (TimeSpan.TryParse(value.Trim(), CultureInfo.InvariantCulture, out parsedSpan) &&
                parsedSpan >= TimeSpan.Zero &&
                parsedSpan < TimeSpan.FromDays(1))
            {
                time = parsedSpan;
                return true;
            }

            return false;
        }

        private static TimeZoneInfo ResolveTimeZone(string timeZoneId)
        {
            if (String.IsNullOrWhiteSpace(timeZoneId))
            {
                return TimeZoneInfo.Local;
            }

            try
            {
                return TimeZoneInfo.FindSystemTimeZoneById(timeZoneId);
            }
            catch
            {
                return TimeZoneInfo.Local;
            }
        }
    }
}
