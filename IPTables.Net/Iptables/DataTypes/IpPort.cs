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

        public static IpPort Parse(String ipPort)
        {
            string[] p = ipPort.Split(new[] {':'});
            IPAddress ip;
            try
            {
                ip = IPAddress.Parse(p[0]);
            }
            catch (Exception)
            {
                return Any;
            }

            if (p.Length != 2)
            {
                return new IpPort(ip, 0);
            }

            try
            {
                return new IpPort(ip, uint.Parse(p[1]));
            }
            catch (Exception)
            {
                return Any;
            }
        }

        public override string ToString()
        {
            return Address + ":" + Port;
        }
    }
}