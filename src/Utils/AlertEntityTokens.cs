using System;
using System.Collections.Generic;
using System.IO;

namespace ArcaneEDR
{
    internal static class AlertEntityTokens
    {
        private static readonly string[] KnownKeys = new[]
        {
            "agent_context",
            "asn",
            "asn_org",
            "command",
            "command_line",
            "country",
            "country_lookup",
            "dns_names",
            "enrichment_source",
            "event_id",
            "grouped_alerts",
            "grouped_category",
            "grouped_rules",
            "host_application",
            "image",
            "item",
            "local",
            "maintenance_context",
            "message",
            "name",
            "owner",
            "parent",
            "parent_command_line",
            "parent_path",
            "parent_pid",
            "path",
            "pid",
            "policy",
            "process",
            "process_command_line",
            "process_path",
            "process_sha256",
            "process_signer",
            "process_user",
            "protocol",
            "query",
            "rdns",
            "reason",
            "reasons",
            "record_id",
            "registrable_domain",
            "remote",
            "remote_host",
            "remote_ip",
            "remote_owner",
            "resolved_domain",
            "script_block",
            "service",
            "sha256",
            "signer",
            "sni_hostname",
            "source",
            "state",
            "target",
            "thread_id",
            "user"
        };

        public static string Get(string entity, string key)
        {
            if (String.IsNullOrWhiteSpace(entity) || String.IsNullOrWhiteSpace(key)) return "";

            string prefix = key + "=";
            int index = entity.IndexOf(prefix, StringComparison.OrdinalIgnoreCase);
            while (index > 0 && !Char.IsWhiteSpace(entity[index - 1]))
            {
                index = entity.IndexOf(prefix, index + prefix.Length, StringComparison.OrdinalIgnoreCase);
            }

            if (index < 0) return "";

            int start = index + prefix.Length;
            int end = FindNextTokenStart(entity, start);
            if (end < 0) end = entity.Length;
            return entity.Substring(start, end - start).Trim().Trim('"');
        }

        public static string FirstNonEmpty(params string[] values)
        {
            if (values == null) return "";
            foreach (string value in values)
            {
                if (!String.IsNullOrWhiteSpace(value)) return value;
            }

            return "";
        }

        public static string FileNameOrValue(string value)
        {
            if (String.IsNullOrWhiteSpace(value)) return "";

            try
            {
                string fileName = Path.GetFileName(value);
                if (!String.IsNullOrWhiteSpace(fileName)) return fileName;
            }
            catch
            {
            }

            return value;
        }

        private static int FindNextTokenStart(string entity, int start)
        {
            if (String.IsNullOrWhiteSpace(entity) || start < 0 || start >= entity.Length) return -1;

            for (int index = start; index < entity.Length; index++)
            {
                if (!Char.IsWhiteSpace(entity[index])) continue;

                int candidate = index + 1;
                while (candidate < entity.Length && Char.IsWhiteSpace(entity[candidate]))
                {
                    candidate++;
                }

                if (candidate >= entity.Length) return -1;
                foreach (string key in KnownKeys)
                {
                    if (HasTokenPrefix(entity, candidate, key))
                    {
                        return index;
                    }
                }
            }

            return -1;
        }

        private static bool HasTokenPrefix(string entity, int index, string key)
        {
            if (String.IsNullOrWhiteSpace(entity) || String.IsNullOrWhiteSpace(key)) return false;

            string prefix = key + "=";
            if (index < 0 || index + prefix.Length > entity.Length) return false;
            return String.Compare(entity, index, prefix, 0, prefix.Length, StringComparison.OrdinalIgnoreCase) == 0;
        }
    }
}
