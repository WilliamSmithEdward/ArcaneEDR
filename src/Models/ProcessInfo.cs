using System;
using System.Globalization;

namespace ArcaneEDR
{
    internal sealed class ProcessInfo
    {
        public int ProcessId;
        public string ProcessName;
        public string ExecutablePath;
        public string CommandLine;
        public int ParentProcessId;
        public string ParentProcessName;
        public string ParentExecutablePath;
        public string ParentCommandLine;
        public string User;
        public int SessionId;
        public DateTime? StartTimeUtc;
        public string Sha256;
        public string Signer;

        public bool HasExecutablePath
        {
            get { return !String.IsNullOrWhiteSpace(ExecutablePath); }
        }

        public bool HasSigner
        {
            get { return !String.IsNullOrWhiteSpace(Signer); }
        }

        public string Summary
        {
            get
            {
                return "process=" + TextFormatting.EmptyIfNull(ProcessName) +
                    " pid=" + ProcessId.ToString(CultureInfo.InvariantCulture) +
                    " path=" + TextFormatting.EmptyIfNull(ExecutablePath) +
                    " command_line=" + TextFormatting.EmptyIfNull(CommandLine) +
                    " parent=" + TextFormatting.EmptyIfNull(ParentProcessName) +
                    " parent_pid=" + ParentProcessId.ToString(CultureInfo.InvariantCulture) +
                    " parent_command_line=" + TextFormatting.EmptyIfNull(ParentCommandLine) +
                    " user=" + TextFormatting.EmptyIfNull(User) +
                    " session=" + SessionId.ToString(CultureInfo.InvariantCulture) +
                    " sha256=" + TextFormatting.EmptyIfNull(Sha256) +
                    " signer=" + TextFormatting.EmptyIfNull(Signer);
            }
        }
    }
}
