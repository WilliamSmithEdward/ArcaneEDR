using System;

namespace ArcaneEDR
{
    internal static class HttpAuthHeader
    {
        public static string NormalizePrefix(string prefix)
        {
            if (String.IsNullOrWhiteSpace(prefix)) return "";
            string trimmed = prefix.Trim();
            if (trimmed.Equals("Bearer", StringComparison.OrdinalIgnoreCase) ||
                trimmed.Equals("Token", StringComparison.OrdinalIgnoreCase))
            {
                return trimmed + " ";
            }

            return prefix;
        }
    }
}
