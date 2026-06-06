using System.Globalization;
using System.Net;

namespace ArcaneEDR
{
    internal sealed class NetworkEndpoint
    {
        public string Protocol;
        public IPAddress LocalAddress;
        public int LocalPort;
        public IPAddress RemoteAddress;
        public int RemotePort;
        public string State;
        public int ProcessId;
        public string ProcessName;
        public string RemoteHost;
        public ProcessInfo Process;
        public string Source;

        public bool IsTcpListener
        {
            get { return Protocol == "TCP" && State == "LISTENING"; }
        }

        public bool IsUdpSocket
        {
            get { return Protocol == "UDP"; }
        }

        public bool IsEstablishedTcp
        {
            get { return Protocol == "TCP" && (State == "ESTABLISHED" || State == "SYSMON") && RemotePort > 0; }
        }

        public string ConnectionKey
        {
            get
            {
                return Protocol + "|" + LocalAddress + "|" + LocalPort.ToString(CultureInfo.InvariantCulture) + "|" +
                    RemoteAddress + "|" + RemotePort.ToString(CultureInfo.InvariantCulture) + "|" +
                    ProcessId.ToString(CultureInfo.InvariantCulture);
            }
        }

        public string EntitySummary
        {
            get
            {
                return "process=" + ProcessName +
                    " pid=" + ProcessId.ToString(CultureInfo.InvariantCulture) +
                    " protocol=" + Protocol +
                    " local=" + LocalAddress + ":" + LocalPort.ToString(CultureInfo.InvariantCulture) +
                    " remote=" + RemoteAddress + ":" + RemotePort.ToString(CultureInfo.InvariantCulture) +
                    " remote_host=" + Safe(RemoteHost) +
                    " state=" + State +
                    " source=" + Safe(Source) +
                    " process_path=" + Safe(Process == null ? "" : Process.ExecutablePath) +
                    " command_line=" + Safe(Process == null ? "" : Process.CommandLine) +
                    " parent=" + Safe(Process == null ? "" : Process.ParentProcessName) +
                    " parent_pid=" + (Process == null ? "" : Process.ParentProcessId.ToString(CultureInfo.InvariantCulture)) +
                    " sha256=" + Safe(Process == null ? "" : Process.Sha256) +
                    " signer=" + Safe(Process == null ? "" : Process.Signer);
            }
        }

        public override string ToString()
        {
            return Protocol + " " + LocalAddress + ":" + LocalPort.ToString(CultureInfo.InvariantCulture) +
                " -> " + RemoteAddress + ":" + RemotePort.ToString(CultureInfo.InvariantCulture) +
                " " + State +
                " pid=" + ProcessId.ToString(CultureInfo.InvariantCulture) +
                " process=" + ProcessName +
                " path=" + Safe(Process == null ? "" : Process.ExecutablePath);
        }

        private static string Safe(string value)
        {
            return value == null ? "" : value;
        }
    }
}
