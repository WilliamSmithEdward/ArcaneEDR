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
                    " process=" + Safe(ProcessName) +
                    " process_path=" + Safe(ProcessPath) +
                    " process_command_line=" + Compact(ProcessCommandLine) +
                    " parent=" + Safe(ParentProcessName) +
                    " parent_pid=" + ParentProcessId.ToString(CultureInfo.InvariantCulture) +
                    " parent_path=" + Safe(ParentProcessPath) +
                    " parent_command_line=" + Compact(ParentCommandLine) +
                    " process_user=" + Safe(ProcessUser) +
                    " process_sha256=" + Safe(ProcessSha256) +
                    " process_signer=" + Safe(ProcessSigner) +
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
                    Safe(ScriptBlockText) + " " + Safe(Message) + " " +
                    Safe(ProcessName) + " " + Safe(ParentProcessName)).Trim();
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
