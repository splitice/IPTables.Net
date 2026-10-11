using System;
using System.Net;

namespace IPTables.Net.Iptables.DataTypes
{
    public struct IpPort
    {
        public static IpPort Any = new IpPort(IPAddress.Any, 0);
        public IPAddress Address;
        public uint Port;

        public IpPort(IPAddress address, uint port)
        {
            Address = address;
            Port = port;
        }

        public static IpPort Parse(string ipPort)
        {
            try
            {
                var parsed = IPPortOrRange.Parse(ipPort);
                if (!parsed.LowerAddress.Equals(parsed.UpperAddress) || parsed.Port.IsRange()) return Any;
                return new IpPort(parsed.LowerAddress, parsed.Port.LowerPort);
            }
            catch (Exception ex) when (ex is ArgumentException || ex is FormatException || ex is OverflowException)
            { return Any; }
        }

        public override string ToString()
        {
            return (Address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6 ? "[" + Address + "]" : Address.ToString()) + ":" + Port;
        }
    }
}