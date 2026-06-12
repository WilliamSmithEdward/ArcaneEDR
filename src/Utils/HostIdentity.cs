using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;

namespace ArcaneEDR
{
    internal sealed class HostIdentitySnapshot
    {
        public string MachineName = "";
        public string DnsHostName = "";
        public readonly List<string> LocalIpAddresses = new List<string>();

        public string LocalIpAddressSummary
        {
            get
            {
                return LocalIpAddresses.Count == 0
                    ? "unavailable"
                    : String.Join(", ", LocalIpAddresses.ToArray());
            }
        }

        public string DisplayName
        {
            get
            {
                if (!String.IsNullOrWhiteSpace(MachineName)) return MachineName;
                if (!String.IsNullOrWhiteSpace(DnsHostName)) return DnsHostName;
                return "unknown";
            }
        }

        public string ToJsonObject()
        {
            return "{" +
                "\"machine_name\":\"" + JsonFields.Escape(MachineName) + "\"," +
                "\"dns_host_name\":\"" + JsonFields.Escape(DnsHostName) + "\"," +
                "\"local_ip_addresses\":" + LocalIpAddressesJson() +
                "}";
        }

        private string LocalIpAddressesJson()
        {
            List<string> encoded = new List<string>();
            foreach (string address in LocalIpAddresses)
            {
                encoded.Add("\"" + JsonFields.Escape(address) + "\"");
            }

            return "[" + String.Join(",", encoded.ToArray()) + "]";
        }
    }

    internal static class HostIdentity
    {
        public static HostIdentitySnapshot Current()
        {
            HostIdentitySnapshot snapshot = new HostIdentitySnapshot();
            snapshot.MachineName = SafeMachineName();
            snapshot.DnsHostName = SafeDnsHostName();
            AddLocalIpAddresses(snapshot);
            return snapshot;
        }

        private static string SafeMachineName()
        {
            try
            {
                return Environment.MachineName ?? "";
            }
            catch
            {
                return "";
            }
        }

        private static string SafeDnsHostName()
        {
            try
            {
                return Dns.GetHostName() ?? "";
            }
            catch
            {
                return "";
            }
        }

        private static void AddLocalIpAddresses(HostIdentitySnapshot snapshot)
        {
            HashSet<string> seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            try
            {
                string hostName = String.IsNullOrWhiteSpace(snapshot.DnsHostName)
                    ? snapshot.MachineName
                    : snapshot.DnsHostName;
                if (String.IsNullOrWhiteSpace(hostName)) return;

                IPAddress[] addresses = Dns.GetHostAddresses(hostName);
                foreach (IPAddress address in addresses)
                {
                    if (!ShouldInclude(address)) continue;
                    string text = address.ToString();
                    if (seen.Add(text))
                    {
                        snapshot.LocalIpAddresses.Add(text);
                    }
                }
            }
            catch
            {
            }
        }

        private static bool ShouldInclude(IPAddress address)
        {
            if (address == null) return false;
            if (IPAddress.IsLoopback(address)) return false;
            if (address.AddressFamily == AddressFamily.InterNetwork) return true;
            if (address.AddressFamily != AddressFamily.InterNetworkV6) return false;
            if (address.IsIPv6LinkLocal || address.IsIPv6Multicast || address.IsIPv6SiteLocal) return false;
            return true;
        }
    }
}
