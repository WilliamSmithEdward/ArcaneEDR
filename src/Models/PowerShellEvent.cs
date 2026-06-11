using System;
using System.Globalization;

namespace ArcaneEDR
{
    internal sealed class PowerShellEvent
    {
        public long RecordId;
        public int EventId;
        public int ProcessId;
        public int ThreadId;
        public DateTime TimestampUtc;
        public string User;
        public string HostApplication;
        public string CommandName;
        public string ScriptBlockText;
        public string Message;
        public string ProcessName;
        public string ProcessPath;
        public string ProcessCommandLine;
        public int ParentProcessId;
        public string ParentProcessName;
        public string ParentProcessPath;
        public string ParentCommandLine;
        public string ProcessUser;
        public string ProcessSha256;
        public string ProcessSigner;

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
                    " pid=" + ProcessId.ToString(CultureInfo.InvariantCulture) +
                    " thread_id=" + ThreadId.ToString(CultureInfo.InvariantCulture) +
                    " process=" + TextFormatting.EmptyIfNull(ProcessName) +
                    " process_path=" + TextFormatting.EmptyIfNull(ProcessPath) +
                    " process_command_line=" + TextFormatting.CompactOrEmpty(ProcessCommandLine, 500) +
                    " parent=" + TextFormatting.EmptyIfNull(ParentProcessName) +
                    " parent_pid=" + ParentProcessId.ToString(CultureInfo.InvariantCulture) +
                    " parent_path=" + TextFormatting.EmptyIfNull(ParentProcessPath) +
                    " parent_command_line=" + TextFormatting.CompactOrEmpty(ParentCommandLine, 500) +
                    " process_user=" + TextFormatting.EmptyIfNull(ProcessUser) +
                    " process_sha256=" + TextFormatting.EmptyIfNull(ProcessSha256) +
                    " process_signer=" + TextFormatting.EmptyIfNull(ProcessSigner) +
                    " user=" + TextFormatting.EmptyIfNull(User) +
                    " command=" + TextFormatting.EmptyIfNull(CommandName) +
                    " host_application=" + TextFormatting.EmptyIfNull(HostApplication) +
                    " script_block=" + TextFormatting.CompactOrEmpty(ScriptBlockText, 500) +
                    " message=" + TextFormatting.CompactOrEmpty(Message, 500);
            }
        }

        public string SearchText
        {
            get
            {
                return (TextFormatting.EmptyIfNull(HostApplication) + " " +
                    TextFormatting.EmptyIfNull(CommandName) + " " +
                    TextFormatting.EmptyIfNull(ScriptBlockText) + " " +
                    TextFormatting.EmptyIfNull(Message) + " " +
                    TextFormatting.EmptyIfNull(ProcessName) + " " +
                    TextFormatting.EmptyIfNull(ParentProcessName)).Trim();
            }
        }

    }
}
