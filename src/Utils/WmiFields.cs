using System;
using System.Management;

namespace ArcaneEDR
{
    internal static class WmiFields
    {
        public static string ReadString(ManagementObject obj, string name)
        {
            if (obj == null || String.IsNullOrWhiteSpace(name)) return "";
            object value = obj[name];
            return value == null ? "" : value.ToString();
        }

        public static int ReadInt(ManagementObject obj, string name)
        {
            object value = obj == null || String.IsNullOrWhiteSpace(name) ? null : obj[name];
            if (value == null) return 0;

            int parsed;
            return Int32.TryParse(value.ToString(), out parsed) ? parsed : 0;
        }
    }
}
