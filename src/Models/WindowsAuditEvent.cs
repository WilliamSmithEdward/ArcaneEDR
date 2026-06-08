using System;
using System.Globalization;

namespace ArcaneEDR
{
    internal sealed class WindowsAuditEvent
    {
        public long RecordId;
        public string LogName;
        public int EventId;
        public DateTime TimestampUtc;
        public string SubjectUser;
        public string TargetUser;
        public string IpAddress;
        public string LogonType;
        public string ProcessName;
        public string ParentProcessName;
        public string ServiceName;
        public string TaskName;
        public string CommandLine;
        public string Message;

        public string CooldownKey
        {
            get
            {
                return Safe(LogName) + "|" +
                    RecordId.ToString(CultureInfo.InvariantCulture) + "|" +
                    EventId.ToString(CultureInfo.InvariantCulture);
            }
        }

        public string EntitySummary
        {
            get
            {
                return "log=" + Safe(LogName) +
                    " event_id=" + EventId.ToString(CultureInfo.InvariantCulture) +
                    " record_id=" + RecordId.ToString(CultureInfo.InvariantCulture) +
                    " subject=" + Safe(SubjectUser) +
                    " target=" + Safe(TargetUser) +
                    " ip=" + Safe(IpAddress) +
                    " logon_type=" + Safe(LogonType) +
                    " process=" + Safe(ProcessName) +
                    " parent=" + Safe(ParentProcessName) +
                    " service=" + Safe(ServiceName) +
                    " task=" + Safe(TaskName) +
                    " command_line=" + Compact(CommandLine);
            }
        }

        public string SearchText
        {
            get
            {
                return (Safe(SubjectUser) + " " + Safe(TargetUser) + " " +
                    Safe(IpAddress) + " " + Safe(ProcessName) + " " +
                    Safe(ParentProcessName) + " " +
                    Safe(ServiceName) + " " + Safe(TaskName) + " " +
                    Safe(CommandLine) + " " + Safe(Message)).Trim();
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
