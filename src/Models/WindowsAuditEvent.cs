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
                return TextFormatting.EmptyIfNull(LogName) + "|" +
                    RecordId.ToString(CultureInfo.InvariantCulture) + "|" +
                    EventId.ToString(CultureInfo.InvariantCulture);
            }
        }

        public string EntitySummary
        {
            get
            {
                return "log=" + TextFormatting.EmptyIfNull(LogName) +
                    " event_id=" + EventId.ToString(CultureInfo.InvariantCulture) +
                    " record_id=" + RecordId.ToString(CultureInfo.InvariantCulture) +
                    " subject=" + TextFormatting.EmptyIfNull(SubjectUser) +
                    " target=" + TextFormatting.EmptyIfNull(TargetUser) +
                    " ip=" + TextFormatting.EmptyIfNull(IpAddress) +
                    " logon_type=" + TextFormatting.EmptyIfNull(LogonType) +
                    " process=" + TextFormatting.EmptyIfNull(ProcessName) +
                    " parent=" + TextFormatting.EmptyIfNull(ParentProcessName) +
                    " service=" + TextFormatting.EmptyIfNull(ServiceName) +
                    " task=" + TextFormatting.EmptyIfNull(TaskName) +
                    " command_line=" + TextFormatting.CompactOrEmpty(CommandLine, 500);
            }
        }

        public string SearchText
        {
            get
            {
                return (TextFormatting.EmptyIfNull(SubjectUser) + " " +
                    TextFormatting.EmptyIfNull(TargetUser) + " " +
                    TextFormatting.EmptyIfNull(IpAddress) + " " +
                    TextFormatting.EmptyIfNull(ProcessName) + " " +
                    TextFormatting.EmptyIfNull(ParentProcessName) + " " +
                    TextFormatting.EmptyIfNull(ServiceName) + " " +
                    TextFormatting.EmptyIfNull(TaskName) + " " +
                    TextFormatting.EmptyIfNull(CommandLine) + " " +
                    TextFormatting.EmptyIfNull(Message)).Trim();
            }
        }

    }
}
