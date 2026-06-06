using System;
using System.Collections.Generic;

namespace ArcaneEDR
{
    internal static class DomainRules
    {
        public static bool HasHighEntropyLabel(string domain)
        {
            if (String.IsNullOrWhiteSpace(domain)) return false;

            string[] labels = domain.Trim().TrimEnd('.').Split('.');
            foreach (string label in labels)
            {
                if (label.Length < 16) continue;
                double entropy = ShannonEntropy(label.ToLowerInvariant());
                double digitRatio = DigitRatio(label);
                if (entropy >= 3.6 && digitRatio >= 0.15) return true;
                if (entropy >= 4.1) return true;
            }

            return false;
        }

        private static double ShannonEntropy(string value)
        {
            Dictionary<char, int> counts = new Dictionary<char, int>();
            foreach (char c in value)
            {
                int count;
                counts.TryGetValue(c, out count);
                counts[c] = count + 1;
            }

            double entropy = 0;
            foreach (int count in counts.Values)
            {
                double p = (double)count / value.Length;
                entropy -= p * Math.Log(p, 2);
            }

            return entropy;
        }

        private static double DigitRatio(string value)
        {
            int digits = 0;
            foreach (char c in value)
            {
                if (Char.IsDigit(c)) digits++;
            }

            return value.Length == 0 ? 0 : (double)digits / value.Length;
        }
    }
}
