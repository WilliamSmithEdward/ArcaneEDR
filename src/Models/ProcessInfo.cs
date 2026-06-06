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
                return "process=" + Safe(ProcessName) +
                    " pid=" + ProcessId.ToString(CultureInfo.InvariantCulture) +
                    " path=" + Safe(ExecutablePath) +
                    " command_line=" + Safe(CommandLine) +
                    " parent=" + Safe(ParentProcessName) +
                    " parent_pid=" + ParentProcessId.ToString(CultureInfo.InvariantCulture) +
                    " parent_command_line=" + Safe(ParentCommandLine) +
                    " user=" + Safe(User) +
                    " session=" + SessionId.ToString(CultureInfo.InvariantCulture) +
                    " sha256=" + Safe(Sha256) +
                    " signer=" + Safe(Signer);
            }
        }

        private static string Safe(string value)
        {
            return value == null ? "" : value;
        }
    }
}
