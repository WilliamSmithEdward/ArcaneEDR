using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography.X509Certificates;
using System.Text.RegularExpressions;

namespace ArcaneEDR
{
    internal sealed class PersistenceTrustResult
    {
        public bool TrustedName;
        public bool TrustedPath;
        public bool TrustedSigner;
        public string ExecutablePath;
        public string Signer;

        public bool Trusted
        {
            get { return TrustedName && (TrustedPath || TrustedSigner); }
        }

        public bool TrustedUserWritablePath
        {
            get { return TrustedName && TrustedPath && TrustedSigner; }
        }
    }

    internal static class PersistenceTrust
    {
        private static readonly object SignerLock = new object();
        private static readonly Dictionary<string, string> SignerCache = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        public static PersistenceTrustResult Evaluate(
            MonitorConfig config,
            string nameValue,
            string pathValue,
            string commandValue,
            string signerValue)
        {
            PersistenceTrustResult result = new PersistenceTrustResult();
            string name = nameValue ?? "";
            string path = pathValue ?? "";
            string command = commandValue ?? "";

            result.TrustedName = HasTrustedName(config, name);
            result.ExecutablePath = ExtractExecutablePath(command);
            if (String.IsNullOrWhiteSpace(result.ExecutablePath))
            {
                result.ExecutablePath = ExtractExecutablePath(path);
            }

            result.Signer = signerValue ?? "";
            if (String.IsNullOrWhiteSpace(result.Signer) && !String.IsNullOrWhiteSpace(result.ExecutablePath))
            {
                result.Signer = GetSignerSubject(result.ExecutablePath);
            }

            result.TrustedPath =
                ContainsConfiguredIndicator(path, config.TrustedPersistencePathIndicators) ||
                ContainsConfiguredIndicator(command, config.TrustedPersistencePathIndicators) ||
                ContainsConfiguredIndicator(result.ExecutablePath, config.TrustedPersistencePathIndicators);
            result.TrustedSigner = MatchesTrustedSigner(config, result.Signer);
            return result;
        }

        public static string ExtractExecutablePath(string text)
        {
            if (String.IsNullOrWhiteSpace(text)) return "";

            string command = ExtractTaskCommand(text);
            if (String.IsNullOrWhiteSpace(command)) command = text;

            command = NormalizePath(Environment.ExpandEnvironmentVariables(command.Trim()));
            if (String.IsNullOrWhiteSpace(command)) return "";

            string quoted = ExtractQuotedPath(command);
            if (!String.IsNullOrWhiteSpace(quoted)) return NormalizePath(quoted);

            Match match = Regex.Match(
                command,
                @"((?:[A-Za-z]:|\\\\[^\\/:*?""<>|\r\n]+\\[^\\/:*?""<>|\r\n]+)\\[^""<>|\r\n]*?\.(?:exe|dll|sys|cmd|bat|ps1|com|scr))",
                RegexOptions.IgnoreCase);
            if (match.Success) return NormalizePath(match.Value);

            return "";
        }

        public static bool ContainsConfiguredIndicator(string text, HashSet<string> indicators)
        {
            if (String.IsNullOrWhiteSpace(text)) return false;

            foreach (string indicator in indicators)
            {
                if (!String.IsNullOrWhiteSpace(indicator) &&
                    text.IndexOf(indicator, StringComparison.OrdinalIgnoreCase) >= 0)
                {
                    return true;
                }
            }

            return false;
        }

        private static bool HasTrustedName(MonitorConfig config, string name)
        {
            foreach (string prefix in config.TrustedPersistenceNamePrefixes)
            {
                if (!String.IsNullOrWhiteSpace(prefix) &&
                    name.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
                {
                    return true;
                }
            }

            return false;
        }

        private static bool MatchesTrustedSigner(MonitorConfig config, string signer)
        {
            if (String.IsNullOrWhiteSpace(signer)) return false;

            foreach (string subject in config.TrustedPersistenceSignerSubjects)
            {
                if (!String.IsNullOrWhiteSpace(subject) &&
                    signer.IndexOf(subject, StringComparison.OrdinalIgnoreCase) >= 0)
                {
                    return true;
                }
            }

            return false;
        }

        private static string GetSignerSubject(string path)
        {
            string normalized = NormalizePath(path);
            if (String.IsNullOrWhiteSpace(normalized) || !File.Exists(normalized)) return "";

            lock (SignerLock)
            {
                string cached;
                if (SignerCache.TryGetValue(normalized, out cached)) return cached;
            }

            string value = "";
            try
            {
                X509Certificate certificate = X509Certificate.CreateFromSignedFile(normalized);
                value = certificate == null ? "" : certificate.Subject;
            }
            catch
            {
                value = "";
            }

            lock (SignerLock)
            {
                SignerCache[normalized] = value;
            }

            return value;
        }

        private static string ExtractTaskCommand(string text)
        {
            Match match = Regex.Match(text, @"<Command>\s*(.*?)\s*</Command>", RegexOptions.IgnoreCase | RegexOptions.Singleline);
            return match.Success ? match.Groups[1].Value : "";
        }

        private static string ExtractQuotedPath(string text)
        {
            if (text.Length < 2) return "";
            char quote = text[0];
            if (quote != '"' && quote != '\'') return "";

            int end = text.IndexOf(quote, 1);
            if (end <= 1) return "";
            return text.Substring(1, end - 1);
        }

        private static string NormalizePath(string path)
        {
            if (String.IsNullOrWhiteSpace(path)) return "";

            string normalized = path.Trim().Trim('"', '\'');
            if (normalized.StartsWith(@"\\??\", StringComparison.OrdinalIgnoreCase))
            {
                normalized = normalized.Substring(@"\\??\".Length);
            }
            else if (normalized.StartsWith(@"\??\", StringComparison.OrdinalIgnoreCase))
            {
                normalized = normalized.Substring(@"\??\".Length);
            }
            else if (normalized.StartsWith(@"\\?\", StringComparison.OrdinalIgnoreCase))
            {
                normalized = normalized.Substring(@"\\?\".Length);
            }
            else if (normalized.StartsWith(@"\SystemRoot\", StringComparison.OrdinalIgnoreCase))
            {
                normalized = Environment.GetFolderPath(Environment.SpecialFolder.Windows) + normalized.Substring(@"\SystemRoot".Length);
            }

            try
            {
                if (Path.IsPathRooted(normalized))
                {
                    normalized = Path.GetFullPath(normalized);
                }
            }
            catch
            {
            }

            return normalized;
        }
    }
}
