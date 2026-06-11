using System;
using System.Globalization;

namespace ArcaneEDR
{
    internal sealed class DnsQueryEvent
    {
        public long RecordId;
        public DateTime TimestampUtc;
        public int ProcessId;
        public string ProcessGuid;
        public string ProcessName;
        public string Image;
        public string User;
        public string QueryName;
        public string QueryStatus;
        public string QueryResults;

        public string CooldownKey
        {
            get
            {
                return "dns|" + ProcessId.ToString(CultureInfo.InvariantCulture) + "|" + QueryName;
            }
        }

        public string EntitySummary
        {
            get
            {
                return "process=" + ProcessName +
                    " pid=" + ProcessId.ToString(CultureInfo.InvariantCulture) +
                    " image=" + TextFormatting.EmptyIfNull(Image) +
                    " user=" + TextFormatting.EmptyIfNull(User) +
                    " query=" + TextFormatting.EmptyIfNull(QueryName) +
                    " status=" + TextFormatting.EmptyIfNull(QueryStatus) +
                    " results=" + TextFormatting.EmptyIfNull(QueryResults);
            }
        }
    }
}
