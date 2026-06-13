using System;
using System.Text.RegularExpressions;

namespace ArcaneEDR
{
    internal static class SensitiveTextRedactor
    {
        public static string RedactForAiPayload(string value, bool redactDomains, bool redactCommandFields)
        {
            return Redact(
                value,
                secretReplacement: "[redacted-secret]",
                jwtReplacement: "[redacted-jwt]",
                emailReplacement: "[redacted-email]",
                urlReplacement: "[redacted-url]",
                domainReplacement: "[redacted-domain]",
                ipReplacement: "[redacted-ip]",
                sha256Replacement: "[redacted-sha256]",
                pathReplacement: "[redacted-path]",
                uncPathReplacement: "[redacted-unc-path]",
                accountReplacement: "[redacted-account]",
                commandReplacement: "[redacted]",
                encodedDataReplacement: "[redacted-encoded-data]",
                redactDomains: redactDomains,
                redactCommandFields: redactCommandFields);
        }

        public static string RedactForDailyReport(string value)
        {
            return RedactForAiPayload(value, true, true);
        }

        public static string RedactForSupportBundle(string value)
        {
            return Redact(
                value,
                secretReplacement: "<redacted>",
                jwtReplacement: "<redacted-jwt>",
                emailReplacement: "<redacted-email>",
                urlReplacement: "<redacted-url>",
                domainReplacement: "<redacted-domain>",
                ipReplacement: "<redacted-ip>",
                sha256Replacement: "<redacted-sha256>",
                pathReplacement: "<redacted-path>",
                uncPathReplacement: "<redacted-unc-path>",
                accountReplacement: "<redacted-account>",
                commandReplacement: "<redacted>",
                encodedDataReplacement: "<redacted-encoded-data>",
                redactDomains: true,
                redactCommandFields: true);
        }

        private static string Redact(
            string value,
            string secretReplacement,
            string jwtReplacement,
            string emailReplacement,
            string urlReplacement,
            string domainReplacement,
            string ipReplacement,
            string sha256Replacement,
            string pathReplacement,
            string uncPathReplacement,
            string accountReplacement,
            string commandReplacement,
            string encodedDataReplacement,
            bool redactDomains,
            bool redactCommandFields)
        {
            if (String.IsNullOrWhiteSpace(value)) return "";

            string result = value;
            result = Regex.Replace(result, "(?i)bearer\\s+[A-Za-z0-9._\\-+/=]{8,}", "Bearer " + secretReplacement);
            result = Regex.Replace(result, "(?i)(api[_-]?key|apikey|token|secret|password|passwd|pwd|authorization|client_secret|access_token|refresh_token)\\s*[:=]\\s*[^\\s,;\\}\\]]+", "$1=" + secretReplacement);
            result = Regex.Replace(result, "[A-Za-z0-9_-]{20,}\\.[A-Za-z0-9_-]{20,}\\.[A-Za-z0-9_-]{10,}", jwtReplacement);
            result = Regex.Replace(result, "[A-Za-z0-9._%+\\-]+@[A-Za-z0-9.\\-]+\\.[A-Za-z]{2,}", emailReplacement);
            result = Regex.Replace(result, "(?i)https?://[^\\s\"'<>]+", urlReplacement);
            if (redactDomains)
            {
                result = Regex.Replace(result, "(?i)\\b(?:[a-z0-9](?:[a-z0-9\\-]{0,61}[a-z0-9])?\\.)+[a-z]{2,}\\b", domainReplacement);
            }

            result = Regex.Replace(result, "\\b(?:\\d{1,3}\\.){3}\\d{1,3}\\b", ipReplacement);
            result = Regex.Replace(result, "(?i)\\b[0-9a-f]{64}\\b", sha256Replacement);
            result = Regex.Replace(result, "(?i)C:\\\\Users\\\\[^\\\\\\s\"']+", "C:\\Users\\" + accountReplacement);
            result = Regex.Replace(result, "(?i)[A-Z]:\\\\[^\\s|,\"']+", pathReplacement);
            result = Regex.Replace(result, "\\\\\\\\[^\\s|,\"']+", uncPathReplacement);
            result = Regex.Replace(result, "(?i)(user|subject|target)=([^\\s|,]+)", "$1=" + accountReplacement);
            if (redactCommandFields)
            {
                result = Regex.Replace(result, "(?i)(command_line|parent_command_line|script_block|decodedpreview)=([^|]+)", "$1=" + commandReplacement);
            }

            result = Regex.Replace(result, "[A-Za-z0-9+/]{80,}={0,2}", encodedDataReplacement);
            return result.Trim();
        }
    }
}
