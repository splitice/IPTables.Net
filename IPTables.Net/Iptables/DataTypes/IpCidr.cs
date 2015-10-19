using System;
using System.Net;
using IPTables.Net.Exceptions;
using IPTables.Net.Supporting;
using LukeSkywalker.IPNetwork;

namespace IPTables.Net.Iptables.DataTypes
{
    public struct IpCidr : IEquatable<IpCidr>
    {
        public static IpCidr Any = new IpCidr(IPAddress.Any, 0);

        public IPAddress Address;
        public uint Cidr;

        public IpCidr(IPAddress address, uint cidr = 32)
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
            catch (Exception ex)
            {
                throw new IpTablesNetException("Invalid IP Address: "+p[0], ex);
            }

            if (p.Length == 1)
            {
                return new IpCidr(ip, 32);
            }

            if (Equals(ip, IPAddress.Any))
            {
                return new IpCidr(ip, 0);
            }

            try
            {
                uint cidrN = uint.Parse(p[1]);
                if (cidrN > 32)
                {
                    throw new IpTablesNetException("Invalid CIDR number (>32) number: "+cidrN);
                }
                return new IpCidr(ip, cidrN);
            }
            catch (Exception ex)
            {
                throw new IpTablesNetException("Invalid CIDR number component", ex);
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