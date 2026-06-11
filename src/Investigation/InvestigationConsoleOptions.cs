using System;
using System.Globalization;

namespace ArcaneEDR
{
    internal static class InvestigationConsoleOptions
    {
        public static TimeSpan ParseLookback(string[] args, TimeSpan fallback)
        {
            string last = OptionValue(args, "--last", "");
            TimeSpan parsed;
            return TryParseDuration(last, out parsed) ? parsed : fallback;
        }

        public static bool TryParseDuration(string value, out TimeSpan result)
        {
            result = TimeSpan.Zero;
            if (String.IsNullOrWhiteSpace(value)) return false;

            string trimmed = value.Trim().ToLowerInvariant();
            double number;
            if (trimmed.EndsWith("m", StringComparison.OrdinalIgnoreCase) &&
                Double.TryParse(trimmed.Substring(0, trimmed.Length - 1), NumberStyles.Float, CultureInfo.InvariantCulture, out number))
            {
                result = TimeSpan.FromMinutes(number);
                return number > 0;
            }

            if (trimmed.EndsWith("h", StringComparison.OrdinalIgnoreCase) &&
                Double.TryParse(trimmed.Substring(0, trimmed.Length - 1), NumberStyles.Float, CultureInfo.InvariantCulture, out number))
            {
                result = TimeSpan.FromHours(number);
                return number > 0;
            }

            if (trimmed.EndsWith("d", StringComparison.OrdinalIgnoreCase) &&
                Double.TryParse(trimmed.Substring(0, trimmed.Length - 1), NumberStyles.Float, CultureInfo.InvariantCulture, out number))
            {
                result = TimeSpan.FromDays(number);
                return number > 0;
            }

            return TimeSpan.TryParse(value, out result) && result > TimeSpan.Zero;
        }

        public static string Describe(TimeSpan value)
        {
            if (value.TotalDays >= 1 && value.TotalDays == Math.Floor(value.TotalDays))
            {
                return value.TotalDays.ToString("0", CultureInfo.InvariantCulture) + "d";
            }

            if (value.TotalHours >= 1 && value.TotalHours == Math.Floor(value.TotalHours))
            {
                return value.TotalHours.ToString("0", CultureInfo.InvariantCulture) + "h";
            }

            return value.TotalMinutes.ToString("0", CultureInfo.InvariantCulture) + "m";
        }

        public static string OptionValue(string[] args, string name, string fallback)
        {
            if (args == null || String.IsNullOrWhiteSpace(name)) return fallback;
            string equalsPrefix = name + "=";
            for (int index = 0; index < args.Length; index++)
            {
                if (args[index].Equals(name, StringComparison.OrdinalIgnoreCase) &&
                    index + 1 < args.Length)
                {
                    return args[index + 1];
                }

                if (args[index].StartsWith(equalsPrefix, StringComparison.OrdinalIgnoreCase))
                {
                    return args[index].Substring(equalsPrefix.Length);
                }
            }

            return fallback;
        }

        public static string CompactForConsole(string value, int maxLength)
        {
            if (String.IsNullOrWhiteSpace(value)) return "unknown";

            string compact = value.Replace("\r", " ").Replace("\n", " ").Replace("\t", " ").Trim();
            while (compact.IndexOf("  ", StringComparison.Ordinal) >= 0)
            {
                compact = compact.Replace("  ", " ");
            }

            if (compact.Length <= maxLength) return compact;
            if (maxLength <= 3) return compact.Substring(0, maxLength);
            return compact.Substring(0, maxLength - 3) + "...";
        }
    }
}
