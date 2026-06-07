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
                    Safe(TargetFilename);
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

                return "process=" + Safe(ProcessName) +
                    " pid=" + ProcessId.ToString(CultureInfo.InvariantCulture) +
                    " image=" + Safe(Image) +
                    " command_line=" + Safe(commandLine) +
                    " parent=" + Safe(parent) +
                    " parent_command_line=" + Safe(parentCommandLine) +
                    " user=" + Safe(User) +
                    " target=" + Safe(TargetFilename) +
                    " signer=" + Safe(signer) +
                    " sha256=" + Safe(sha256) +
                    " observed_utc=" + TimestampUtc.ToString("yyyy-MM-ddTHH:mm:ssZ", CultureInfo.InvariantCulture);
            }
        }

        private static string Safe(string value)
        {
            return value == null ? "" : value;
        }
    }
}
