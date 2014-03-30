using System;
using System.Net;
using IPTables.Net.Supporting;
using LukeSkywalker.IPNetwork;

namespace IPTables.Net.Iptables.DataTypes
{
    public struct IpCidr : IEquatable<IpCidr>
    {
        public static IpCidr Any = new IpCidr(IPAddress.Any, 0);

        public IPAddress Address;
        public uint Cidr;

        public IpCidr(IPAddress address, uint cidr)
        {
            Address = address;
            Cidr = cidr;
        }

        public IPNetwork GetIPNetwork()
        {
            return IPNetwork.Parse(Address, IPNetwork.ToNetmask((byte)Cidr));
        }

        public bool Equals(IpCidr other)
        {
            return other.Address.Equals(Address) && other.Cidr == Cidr;
        }

        public static IpCidr Parse(String cidr)
        {
            string[] p = cidr.Split(new[] {'/'});
            IPAddress ip;
            try
            {
                ip = IPAddress.Parse(p[0]);
            }
            catch (Exception)
            {
                return Any;
            }

            if (p.Length == 1)
            {
                return new IpCidr(ip, 32);
            }

            try
            {
                return new IpCidr(ip, uint.Parse(p[1]));
            }
            catch (Exception)
            {
                return Any;
            }
        }

        public static bool operator ==(IpCidr a, IpCidr b)
        {
            return a.Equals(b);
        }

        public static bool operator !=(IpCidr a, IpCidr b)
        {
            return !(a == b);
        }

        public override string ToString()
        {
            if (Cidr == 32)
            {
                return Address.ToString();
            }
            return Address + "/" + Cidr;
        }

        public bool Contains(IpCidr cidr)
        {
            var thisNetwork = GetIPNetwork();
            var innerNetwork = cidr.GetIPNetwork();

            if (thisNetwork.Network.ToInt() <= innerNetwork.Network.ToInt() &&
                thisNetwork.Broadcast.ToInt() >= innerNetwork.Broadcast.ToInt())
            {
                return true;
            }

            return false;
        }
    }
}