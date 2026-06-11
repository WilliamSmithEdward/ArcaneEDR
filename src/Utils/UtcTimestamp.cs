using System;
using System.Globalization;

namespace ArcaneEDR
{
    internal static class UtcTimestamp
    {
        public static bool TryParse(string value, out DateTime result)
        {
            result = DateTime.MinValue;
            if (String.IsNullOrWhiteSpace(value)) return false;

            DateTime parsed;
            if (!DateTime.TryParse(value, CultureInfo.InvariantCulture, DateTimeStyles.AdjustToUniversal, out parsed))
            {
                return false;
            }

            result = parsed.ToUniversalTime();
            return true;
        }

        public static string Format(DateTime value)
        {
            return value.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ", CultureInfo.InvariantCulture);
        }

        public static string Format(DateTime? value)
        {
            return value.HasValue ? Format(value.Value) : "";
        }
    }
}
