using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.Net;

namespace ArcaneEDR
{
    internal sealed class NetstatNetworkSnapshotCollector : INetworkSnapshotCollector
    {
        private readonly FileLogger logger;
        private readonly IProcessEnricher processEnricher;

        public NetstatNetworkSnapshotCollector(FileLogger logger, IProcessEnricher processEnricher)
        {
            this.logger = logger;
            this.processEnricher = processEnricher;
        }

        public NetworkSnapshot Capture()
        {
            ProcessStartInfo startInfo = new ProcessStartInfo("netstat.exe", "-ano")
            {
                CreateNoWindow = true,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true
            };

            using (Process process = Process.Start(startInfo))
            {
                string output = process.StandardOutput.ReadToEnd();
                string error = process.StandardError.ReadToEnd();
                process.WaitForExit(10000);

                if (!String.IsNullOrWhiteSpace(error))
                {
                    logger.Warn("netstat stderr: " + error.Trim());
                }

                Dictionary<int, ProcessInfo> processes = processEnricher.CaptureProcesses();
                return new NetworkSnapshot(Parse(output, processes));
            }
        }

        private static List<NetworkEndpoint> Parse(string output, Dictionary<int, ProcessInfo> processes)
        {
            List<NetworkEndpoint> endpoints = new List<NetworkEndpoint>();
            Dictionary<int, string> processNames = new Dictionary<int, string>();

            foreach (string line in output.Split(new[] { "\r\n", "\n" }, StringSplitOptions.None))
            {
                string trimmed = line.Trim();
                if (!trimmed.StartsWith("TCP", StringComparison.OrdinalIgnoreCase) &&
                    !trimmed.StartsWith("UDP", StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }

                string[] parts = trimmed.Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries);
                try
                {
                    NetworkEndpoint endpoint = new NetworkEndpoint();
                    endpoint.Protocol = parts[0].ToUpperInvariant();
                    endpoint.LocalAddress = ParseAddressPort(parts[1], out endpoint.LocalPort);

                    if (endpoint.Protocol == "TCP")
                    {
                        endpoint.RemoteAddress = ParseAddressPort(parts[2], out endpoint.RemotePort);
                        endpoint.State = parts[3].ToUpperInvariant();
                        endpoint.ProcessId = Int32.Parse(parts[4], CultureInfo.InvariantCulture);
                    }
                    else
                    {
                        endpoint.RemoteAddress = IPAddress.None;
                        endpoint.RemotePort = 0;
                        endpoint.State = "UDP";
                        endpoint.ProcessId = Int32.Parse(parts[3], CultureInfo.InvariantCulture);
                    }

                    string processName;
                    if (!processNames.TryGetValue(endpoint.ProcessId, out processName))
                    {
                        ProcessInfo processInfo;
                        if (processes.TryGetValue(endpoint.ProcessId, out processInfo))
                        {
                            processName = processInfo.ProcessName;
                            endpoint.Process = processInfo;
                        }
                        else
                        {
                            processName = ResolveProcessName(endpoint.ProcessId);
                        }

                        processNames[endpoint.ProcessId] = processName;
                    }
                    else
                    {
                        ProcessInfo processInfo;
                        if (processes.TryGetValue(endpoint.ProcessId, out processInfo))
                        {
                            endpoint.Process = processInfo;
                        }
                    }

                    endpoint.ProcessName = processName;
                    endpoint.Source = "netstat";
                    endpoints.Add(endpoint);
                }
                catch
                {
                }
            }

            return endpoints;
        }

        private static IPAddress ParseAddressPort(string text, out int port)
        {
            port = 0;
            if (text == "*:*")
            {
                return IPAddress.None;
            }

            int split = text.LastIndexOf(':');
            if (split < 0)
            {
                return IPAddress.None;
            }

            string addressText = text.Substring(0, split).Trim('[', ']');
            string portText = text.Substring(split + 1);
            if (portText != "*") Int32.TryParse(portText, out port);

            if (addressText == "*" || addressText == "0.0.0.0") return IPAddress.Any;
            if (addressText == "::") return IPAddress.IPv6Any;

            IPAddress address;
            return IPAddress.TryParse(addressText, out address) ? address : IPAddress.None;
        }

        private static string ResolveProcessName(int processId)
        {
            if (processId == 0) return "System";
            try
            {
                return Process.GetProcessById(processId).ProcessName + ".exe";
            }
            catch
            {
                return "pid-" + processId.ToString(CultureInfo.InvariantCulture);
            }
        }
    }
}
