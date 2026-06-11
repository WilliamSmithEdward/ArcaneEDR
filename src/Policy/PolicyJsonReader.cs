using System;
using System.Collections;
using System.Globalization;

namespace ArcaneEDR
{
    internal static class PolicyJsonReader
    {
        public static string CanonicalAction(string action)
        {
            if (action == null) return "";
            return action.Trim().Replace("-", "_").Replace(" ", "_").ToLowerInvariant();
        }

        public static object Value(IDictionary map, string key)
        {
            if (map == null || String.IsNullOrWhiteSpace(key)) return null;
            foreach (DictionaryEntry entry in map)
            {
                if (Key(entry.Key).Equals(key, StringComparison.OrdinalIgnoreCase))
                {
                    return entry.Value;
                }
            }

            return null;
        }

        public static string ReadString(IDictionary map, string key)
        {
            object value = Value(map, key);
            return value == null ? "" : value.ToString().Trim();
        }

        public static bool ReadBool(IDictionary map, string key, bool fallback)
        {
            object value = Value(map, key);
            if (value == null) return fallback;
            if (value is bool) return (bool)value;

            bool parsed;
            return Boolean.TryParse(value.ToString(), out parsed) ? parsed : fallback;
        }

        public static int ReadInt(IDictionary map, string key, int fallback, out bool found)
        {
            found = false;
            object value = Value(map, key);
            if (value == null) return fallback;
            found = true;

            int parsed;
            return Int32.TryParse(value.ToString(), NumberStyles.Integer, CultureInfo.InvariantCulture, out parsed)
                ? parsed
                : fallback;
        }

        public static string Key(object key)
        {
            return key == null ? "" : key.ToString();
        }

        public static bool TryParsePortRange(string value, out int start, out int end)
        {
            start = 0;
            end = 0;
            if (String.IsNullOrWhiteSpace(value)) return false;

            string[] parts = value.Trim().Split('-');
            if (parts.Length == 1)
            {
                if (!Int32.TryParse(parts[0], out start)) return false;
                end = start;
            }
            else if (parts.Length == 2)
            {
                if (!Int32.TryParse(parts[0], out start)) return false;
                if (!Int32.TryParse(parts[1], out end)) return false;
            }
            else
            {
                return false;
            }

            return start >= 0 && end <= 65535 && start <= end;
        }
    }
}
