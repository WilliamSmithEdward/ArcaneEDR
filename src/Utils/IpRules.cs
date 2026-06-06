using System.Net;
using System.Net.Sockets;

namespace ArcaneEDR
{
    internal static class IpRules
    {
        public static bool IsExternal(IPAddress address)
        {
            if (!IsUsableAddress(address)) return false;
            if (IPAddress.IsLoopback(address)) return false;
            if (IsPrivateNetwork(address)) return false;

            byte[] bytes = address.GetAddressBytes();
            if (address.AddressFamily == AddressFamily.InterNetwork)
            {
                if (bytes[0] == 169 && bytes[1] == 254) return false;
                if (bytes[0] >= 224) return false;
                return true;
            }

            if (address.AddressFamily == AddressFamily.InterNetworkV6)
            {
                if (address.IsIPv6LinkLocal || address.IsIPv6Multicast || address.IsIPv6SiteLocal) return false;
                if (bytes[0] == 0xfc || bytes[0] == 0xfd) return false;
                return true;
            }

            return false;
        }

        public static bool IsPrivateNetwork(IPAddress address)
        {
            if (!IsUsableAddress(address)) return false;

            byte[] bytes = address.GetAddressBytes();
            if (address.AddressFamily == AddressFamily.InterNetwork)
            {
                if (bytes[0] == 10) return true;
                if (bytes[0] == 172 && bytes[1] >= 16 && bytes[1] <= 31) return true;
                if (bytes[0] == 192 && bytes[1] == 168) return true;
                return false;
            }

            if (address.AddressFamily == AddressFamily.InterNetworkV6)
            {
                return bytes[0] == 0xfc || bytes[0] == 0xfd || address.IsIPv6SiteLocal;
            }

            return false;
        }

        private static bool IsUsableAddress(IPAddress address)
        {
            return address != null &&
                !address.Equals(IPAddress.None) &&
                !address.Equals(IPAddress.Any) &&
                !address.Equals(IPAddress.IPv6Any);
        }
    }
}
