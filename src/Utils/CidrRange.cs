using System;
using System.Net;
using System.Net.Sockets;

namespace ArcaneEDR
{
    internal sealed class CidrRange
    {
        private readonly byte[] network;
        private readonly int prefixLength;
        private readonly AddressFamily family;

        private CidrRange(IPAddress networkAddress, int prefixLength)
        {
            network = networkAddress.GetAddressBytes();
            this.prefixLength = prefixLength;
            family = networkAddress.AddressFamily;
        }

        public static bool TryParse(string text, out CidrRange range)
        {
            range = null;
            if (String.IsNullOrWhiteSpace(text)) return false;

            string[] parts = text.Split('/');
            IPAddress address;
            if (!IPAddress.TryParse(parts[0], out address)) return false;

            int maxPrefix = address.AddressFamily == AddressFamily.InterNetwork ? 32 : 128;
            int prefix = maxPrefix;
            if (parts.Length == 2 && !Int32.TryParse(parts[1], out prefix)) return false;
            if (prefix < 0 || prefix > maxPrefix) return false;

            range = new CidrRange(address, prefix);
            return true;
        }

        public bool Contains(IPAddress address)
        {
            if (address == null || address.AddressFamily != family) return false;
            byte[] candidate = address.GetAddressBytes();
            int fullBytes = prefixLength / 8;
            int remainingBits = prefixLength % 8;

            for (int i = 0; i < fullBytes; i++)
            {
                if (candidate[i] != network[i]) return false;
            }

            if (remainingBits == 0) return true;

            int mask = 0xff << (8 - remainingBits);
            return (candidate[fullBytes] & mask) == (network[fullBytes] & mask);
        }
    }
}
