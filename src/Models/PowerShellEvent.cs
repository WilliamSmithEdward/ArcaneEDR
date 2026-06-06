using System;
using System.Globalization;

namespace ArcaneEDR
{
    internal sealed class PowerShellEvent
    {
        public long RecordId;
        public int EventId;
        public DateTime TimestampUtc;
        public string User;
        public string HostApplication;
        public string CommandName;
        public string ScriptBlockText;
        public string Message;

        public string CooldownKey
        {
            get
            {
                return RecordId.ToString(CultureInfo.InvariantCulture) + "|" +
                    EventId.ToString(CultureInfo.InvariantCulture);
            }
        }

        public string EntitySummary
        {
            get
            {
                return "event_id=" + EventId.ToString(CultureInfo.InvariantCulture) +
                    " record_id=" + RecordId.ToString(CultureInfo.InvariantCulture) +
                    " user=" + Safe(User) +
                    " command=" + Safe(CommandName) +
                    " host_application=" + Safe(HostApplication) +
                    " script_block=" + Compact(ScriptBlockText) +
                    " message=" + Compact(Message);
            }
        }

        public string SearchText
        {
            get
            {
                return (Safe(HostApplication) + " " + Safe(CommandName) + " " +
                    Safe(ScriptBlockText) + " " + Safe(Message)).Trim();
            }
        }

        private static string Safe(string value)
        {
            return value == null ? "" : value;
        }

        private static string Compact(string value)
        {
            if (String.IsNullOrWhiteSpace(value)) return "";
            string compact = value.Replace("\r", " ").Replace("\n", " ").Trim();
            return compact.Length <= 500 ? compact : compact.Substring(0, 500) + "...";
        }
    }
}
