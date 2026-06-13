using System;
using System.Collections;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Web.Script.Serialization;

namespace ArcaneEDR
{
    internal static class PolicyJsonReader
    {
        private static readonly string[] KnownUnifiedPolicyRootFields = new[]
        {
            "policies",
            "rules",
            "remote_endpoint_policies",
            "remoteEndpointPolicies",
            "detection_policies",
            "detectionPolicies",
            "allowlists",
            "blocklists",
            "response_policy",
            "responsePolicy",
            "schema",
            "version",
            "description"
        };

        public static string CanonicalAction(string action)
        {
            if (action == null) return "";
            return action.Trim().Replace("-", "_").Replace(" ", "_").ToLowerInvariant();
        }

        public static object DeserializeFile(string path)
        {
            string json = File.ReadAllText(path);
            JavaScriptSerializer serializer = new JavaScriptSerializer();
            return serializer.DeserializeObject(json);
        }

        public static IList ReadEntriesFromUnifiedRoot(
            object parsed,
            string[] entryKeys,
            List<string> warnings,
            string warningPrefix)
        {
            IList direct = parsed as IList;
            if (direct != null) return direct;

            IDictionary root = parsed as IDictionary;
            if (root == null) return null;

            WarnUnknownUnifiedRootFields(root, warnings, warningPrefix);

            foreach (string key in entryKeys)
            {
                object entries = Value(root, key);
                if (entries != null) return entries as IList;
            }

            return null;
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

        private static void WarnUnknownUnifiedRootFields(IDictionary root, List<string> warnings, string warningPrefix)
        {
            if (warnings == null) return;

            foreach (DictionaryEntry entry in root)
            {
                string key = Key(entry.Key);
                if (!IsKnownUnifiedRootField(key))
                {
                    warnings.Add(warningPrefix + " contains an unknown field: " + key);
                }
            }
        }

        private static bool IsKnownUnifiedRootField(string key)
        {
            foreach (string known in KnownUnifiedPolicyRootFields)
            {
                if (known.Equals(key, StringComparison.OrdinalIgnoreCase)) return true;
            }

            return false;
        }
    }
}
