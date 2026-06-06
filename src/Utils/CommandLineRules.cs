using System;
using System.Text;
using System.Text.RegularExpressions;

namespace ArcaneEDR
{
    internal static class CommandLineRules
    {
        private static readonly Regex Base64Candidate = new Regex(@"[A-Za-z0-9+/]{80,}={0,2}", RegexOptions.Compiled);

        public static EncodedCommandFinding FindEncodedCommand(string commandLine, MonitorConfig config)
        {
            if (!config.DetectEncodedCommandLines || String.IsNullOrWhiteSpace(commandLine))
            {
                return EncodedCommandFinding.None;
            }

            MatchCollection matches = Base64Candidate.Matches(commandLine);
            foreach (Match match in matches)
            {
                if (match.Value.Length < config.EncodedCommandMinimumLength) continue;

                string decoded = TryDecode(match.Value);
                if (String.IsNullOrWhiteSpace(decoded))
                {
                    return new EncodedCommandFinding(true, "base64-like argument could not be decoded safely", "");
                }

                if (LooksExecutable(decoded))
                {
                    return new EncodedCommandFinding(true, "decoded command contains execution or download indicators", Truncate(decoded, 500));
                }
            }

            if (ContainsEncodedSwitch(commandLine))
            {
                return new EncodedCommandFinding(true, "encoded-command switch present", "");
            }

            return EncodedCommandFinding.None;
        }

        private static bool ContainsEncodedSwitch(string commandLine)
        {
            return commandLine.IndexOf("-enc", StringComparison.OrdinalIgnoreCase) >= 0 ||
                commandLine.IndexOf("-encodedcommand", StringComparison.OrdinalIgnoreCase) >= 0 ||
                commandLine.IndexOf("/encodedcommand", StringComparison.OrdinalIgnoreCase) >= 0 ||
                commandLine.IndexOf("frombase64string", StringComparison.OrdinalIgnoreCase) >= 0;
        }

        private static string TryDecode(string value)
        {
            try
            {
                byte[] bytes = Convert.FromBase64String(Pad(value));
                string unicode = Encoding.Unicode.GetString(bytes);
                if (ReadableRatio(unicode) >= 0.65) return unicode;

                string utf8 = Encoding.UTF8.GetString(bytes);
                if (ReadableRatio(utf8) >= 0.65) return utf8;
            }
            catch
            {
            }

            return "";
        }

        private static string Pad(string value)
        {
            int remainder = value.Length % 4;
            if (remainder == 0) return value;
            return value + new string('=', 4 - remainder);
        }

        private static double ReadableRatio(string value)
        {
            if (String.IsNullOrEmpty(value)) return 0;
            int readable = 0;
            foreach (char c in value)
            {
                if (!Char.IsControl(c) || c == '\r' || c == '\n' || c == '\t') readable++;
            }

            return (double)readable / value.Length;
        }

        private static bool LooksExecutable(string decoded)
        {
            string value = decoded.ToLowerInvariant();
            return value.Contains("iex") ||
                value.Contains("invoke-expression") ||
                value.Contains("invoke-webrequest") ||
                value.Contains("downloadstring") ||
                value.Contains("downloadfile") ||
                value.Contains("new-object net.webclient") ||
                value.Contains("start-process") ||
                value.Contains("http://") ||
                value.Contains("https://") ||
                value.Contains("frombase64string") ||
                value.Contains("set-mppreference") ||
                value.Contains("add-mppreference") ||
                value.Contains("bypass") ||
                value.Contains("hidden");
        }

        private static string Truncate(string value, int max)
        {
            if (value == null) return "";
            return value.Length <= max ? value : value.Substring(0, max) + "...";
        }
    }

    internal sealed class EncodedCommandFinding
    {
        public static readonly EncodedCommandFinding None = new EncodedCommandFinding(false, "", "");

        public EncodedCommandFinding(bool detected, string reason, string decodedPreview)
        {
            Detected = detected;
            Reason = reason;
            DecodedPreview = decodedPreview;
        }

        public bool Detected { get; private set; }
        public string Reason { get; private set; }
        public string DecodedPreview { get; private set; }
    }
}
