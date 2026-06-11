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
                return TextFormatting.EmptyIfNull(Type) + "|" +
                    TextFormatting.EmptyIfNull(Name) + "|" +
                    TextFormatting.EmptyIfNull(Path) + "|" +
                    TextFormatting.EmptyIfNull(Command);
            }
        }

        public string EntitySummary
        {
            get
            {
                return "type=" + TextFormatting.EmptyIfNull(Type) +
                    " name=" + TextFormatting.EmptyIfNull(Name) +
                    " path=" + TextFormatting.EmptyIfNull(Path) +
                    " command=" + TextFormatting.EmptyIfNull(Command) +
                    " source=" + TextFormatting.EmptyIfNull(Source) +
                    " signer=" + TextFormatting.EmptyIfNull(Signer) +
                    " observed_utc=" + UtcTimestamp.Format(ObservedUtc);
            }
        }

        public string SearchText
        {
            get
            {
                return (TextFormatting.EmptyIfNull(Type) + " " +
                    TextFormatting.EmptyIfNull(Name) + " " +
                    TextFormatting.EmptyIfNull(Path) + " " +
                    TextFormatting.EmptyIfNull(Command) + " " +
                    TextFormatting.EmptyIfNull(Source) + " " +
                    TextFormatting.EmptyIfNull(Signer)).Trim();
            }
        }
    }
}
