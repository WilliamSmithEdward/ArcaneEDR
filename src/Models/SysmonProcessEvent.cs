using System;
using System.Globalization;

namespace ArcaneEDR
{
    internal sealed class SysmonProcessEvent
    {
        public long RecordId;
        public DateTime TimestampUtc;
        public string ProcessGuid;
        public int ProcessId;
        public string Image;
        public string ProcessName;
        public string CommandLine;
        public string CurrentDirectory;
        public string User;
        public string Hashes;
        public string ParentProcessGuid;
        public int ParentProcessId;
        public string ParentImage;
        public string ParentProcessName;
        public string ParentCommandLine;

        public string EntitySummary
        {
            get
            {
                return "process=" + Safe(ProcessName) +
                    " pid=" + ProcessId.ToString(CultureInfo.InvariantCulture) +
                    " image=" + Safe(Image) +
                    " command_line=" + Safe(CommandLine) +
                    " parent=" + Safe(ParentProcessName) +
                    " parent_pid=" + ParentProcessId.ToString(CultureInfo.InvariantCulture) +
                    " parent_image=" + Safe(ParentImage) +
                    " parent_command_line=" + Safe(ParentCommandLine) +
                    " user=" + Safe(User) +
                    " hashes=" + Safe(Hashes);
            }
        }

        private static string Safe(string value)
        {
            return value == null ? "" : value;
        }
    }
}
