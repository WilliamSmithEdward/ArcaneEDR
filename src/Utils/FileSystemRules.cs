using System;

namespace ArcaneEDR
{
    internal static class FileSystemRules
    {
        public static bool IsUserWritablePath(string path, MonitorConfig config)
        {
            if (String.IsNullOrWhiteSpace(path)) return false;

            string normalized = path.ToLowerInvariant();
            foreach (string indicator in config.UserWritablePathIndicators)
            {
                if (indicator.Length > 0 && normalized.Contains(indicator.ToLowerInvariant()))
                {
                    return true;
                }
            }

            return false;
        }

        public static bool ContainsAny(string value, System.Collections.Generic.HashSet<string> terms)
        {
            if (String.IsNullOrWhiteSpace(value)) return false;

            foreach (string term in terms)
            {
                if (term.Length > 0 && value.IndexOf(term, StringComparison.OrdinalIgnoreCase) >= 0)
                {
                    return true;
                }
            }

            return false;
        }
    }
}
