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
                return "process=" + TextFormatting.EmptyIfNull(ProcessName) +
                    " pid=" + ProcessId.ToString(CultureInfo.InvariantCulture) +
                    " image=" + TextFormatting.EmptyIfNull(Image) +
                    " command_line=" + TextFormatting.EmptyIfNull(CommandLine) +
                    " parent=" + TextFormatting.EmptyIfNull(ParentProcessName) +
                    " parent_pid=" + ParentProcessId.ToString(CultureInfo.InvariantCulture) +
                    " parent_image=" + TextFormatting.EmptyIfNull(ParentImage) +
                    " parent_command_line=" + TextFormatting.EmptyIfNull(ParentCommandLine) +
                    " user=" + TextFormatting.EmptyIfNull(User) +
                    " hashes=" + TextFormatting.EmptyIfNull(Hashes);
            }
        }
    }
}
