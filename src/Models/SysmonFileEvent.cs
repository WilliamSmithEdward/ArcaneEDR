using System;
using System.Globalization;

namespace ArcaneEDR
{
    internal sealed class SysmonFileEvent
    {
        public long RecordId;
        public DateTime TimestampUtc;
        public string ProcessGuid;
        public int ProcessId;
        public string Image;
        public string ProcessName;
        public string TargetFilename;
        public string User;
        public ProcessInfo Process;

        public string CooldownKey
        {
            get
            {
                return RecordId.ToString(CultureInfo.InvariantCulture) + "|" +
                    ProcessId.ToString(CultureInfo.InvariantCulture) + "|" +
                    TextFormatting.EmptyIfNull(TargetFilename);
            }
        }

        public string EntitySummary
        {
            get
            {
                ProcessInfo process = Process;
                string commandLine = process == null ? "" : process.CommandLine;
                string parent = process == null ? "" : process.ParentProcessName;
                string parentCommandLine = process == null ? "" : process.ParentCommandLine;
                string signer = process == null ? "" : process.Signer;
                string sha256 = process == null ? "" : process.Sha256;

                return "process=" + TextFormatting.EmptyIfNull(ProcessName) +
                    " pid=" + ProcessId.ToString(CultureInfo.InvariantCulture) +
                    " image=" + TextFormatting.EmptyIfNull(Image) +
                    " command_line=" + TextFormatting.EmptyIfNull(commandLine) +
                    " parent=" + TextFormatting.EmptyIfNull(parent) +
                    " parent_command_line=" + TextFormatting.EmptyIfNull(parentCommandLine) +
                    " user=" + TextFormatting.EmptyIfNull(User) +
                    " target=" + TextFormatting.EmptyIfNull(TargetFilename) +
                    " signer=" + TextFormatting.EmptyIfNull(signer) +
                    " sha256=" + TextFormatting.EmptyIfNull(sha256) +
                    " observed_utc=" + UtcTimestamp.Format(TimestampUtc);
            }
        }
    }
}
