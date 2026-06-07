using System;
using System.Globalization;

namespace ArcaneEDR
{
    internal sealed class PersistenceItem
    {
        public string Type;
        public string Name;
        public string Path;
        public string Command;
        public string Source;
        public string Signer;
        public DateTime ObservedUtc;

        public string Identity
        {
            get
            {
                return Safe(Type) + "|" + Safe(Name) + "|" + Safe(Path) + "|" + Safe(Command);
            }
        }

        public string EntitySummary
        {
            get
            {
                return "type=" + Safe(Type) +
                    " name=" + Safe(Name) +
                    " path=" + Safe(Path) +
                    " command=" + Safe(Command) +
                    " source=" + Safe(Source) +
                    " signer=" + Safe(Signer) +
                    " observed_utc=" + ObservedUtc.ToString("yyyy-MM-ddTHH:mm:ssZ", CultureInfo.InvariantCulture);
            }
        }

        public string SearchText
        {
            get
            {
                return (Safe(Type) + " " + Safe(Name) + " " + Safe(Path) + " " +
                    Safe(Command) + " " + Safe(Source) + " " + Safe(Signer)).Trim();
            }
        }

        private static string Safe(string value)
        {
            return value == null ? "" : value;
        }
    }
}
