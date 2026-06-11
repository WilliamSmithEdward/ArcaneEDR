using System;
using System.Collections;
using System.Collections.Generic;

namespace ArcaneEDR
{
    internal static class JsonFields
    {
        public static string ExtractObject(string text)
        {
            if (text == null) return "";
            int start = text.IndexOf('{');
            int end = text.LastIndexOf('}');
            if (start >= 0 && end > start) return text.Substring(start, end - start + 1);
            return text;
        }

        public static bool ReadBool(object parsed, string key)
        {
            object value;
            if (!TryGet(parsed, key, out value) || value == null) return false;
            if (value is bool) return (bool)value;
            return value.ToString().Equals("true", StringComparison.OrdinalIgnoreCase);
        }

        public static int ReadInt(object parsed, string key)
        {
            object valueObject;
            if (!TryGet(parsed, key, out valueObject) || valueObject == null) return 0;
            int value;
            return Int32.TryParse(valueObject.ToString(), out value) ? value : 0;
        }

        public static string ReadString(object parsed, string key)
        {
            object value;
            return TryGet(parsed, key, out value) && value != null ? value.ToString() : "";
        }

        public static string Escape(string value)
        {
            if (value == null) return "";
            return value
                .Replace("\\", "\\\\")
                .Replace("\"", "\\\"")
                .Replace("\r", "\\r")
                .Replace("\n", "\\n")
                .Replace("\t", "\\t");
        }

        private static bool TryGet(object parsed, string key, out object value)
        {
            value = null;
            if (parsed == null || String.IsNullOrWhiteSpace(key)) return false;

            IDictionary<string, object> typed = parsed as IDictionary<string, object>;
            if (typed != null)
            {
                return typed.TryGetValue(key, out value);
            }

            IDictionary map = parsed as IDictionary;
            if (map == null || !map.Contains(key)) return false;
            value = map[key];
            return true;
        }
    }
}
