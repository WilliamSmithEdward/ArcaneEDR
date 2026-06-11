using System;

namespace ArcaneEDR
{
    internal static class CountryCodes
    {
        public static bool IsTwoLetterCode(string value)
        {
            if (String.IsNullOrWhiteSpace(value) || value.Length != 2) return false;
            return Char.IsLetter(value[0]) && Char.IsLetter(value[1]);
        }

        public static string NormalizeTwoLetterCode(string value)
        {
            return IsTwoLetterCode(value) ? value.ToUpperInvariant() : "";
        }
    }
}
