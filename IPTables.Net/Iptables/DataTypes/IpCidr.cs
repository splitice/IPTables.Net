using System;
using System.Net;
using System.Net.Sockets;
using IPTables.Net.Exceptions;
using IPTables.Net.Supporting;

namespace IPTables.Net.Iptables.DataTypes
{
    public struct IpCidr : IEquatable<IpCidr>
    {
        public static IpCidr Any = new IpCidr(IPAddress.Any, 0);

        public IPAddress Address;
        public uint Prefix;

        public IpCidr(IPAddress address, uint prefix)
        {
            Address = address;
            Prefix = prefix;
        }

        public IpCidr(IPAddress address)
        {
            Address = address;
            Prefix = (address.AddressFamily == AddressFamily.InterNetworkV6) ? (uint)128 : 32;
        }

        public IPNetwork GetIPNetwork()
        {
            return IPNetwork.Parse(Address, IPNetwork.ToNetmask((byte)Prefix, Address.AddressFamily));
        }

        public bool Equals(IpCidr other)
        {
            return other.Address.Equals(Address) && other.Prefix == Prefix;
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
                return new IpCidr(ip);
            }

            if (Equals(ip, IPAddress.Any))
            {
                return new IpCidr(ip, 0);
            }

            try
            {
                uint cidrN = uint.Parse(p[1]);
                if (ip.AddressFamily == AddressFamily.InterNetwork)
                {
                    if (cidrN > 32)
                    {
                        throw new IpTablesNetException("Invalid CIDR number (>32) number: " + cidrN);
                    }
                }
                else if (ip.AddressFamily == AddressFamily.InterNetworkV6)
                {
                    if (cidrN > 128)
                    {
                        throw new IpTablesNetException("Invalid CIDR number (>128) number: " + cidrN);
                    }
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
            if ((Prefix == 32 && Address.AddressFamily == AddressFamily.InterNetwork) || Prefix == 128)
            {
                return Address.ToString();
            }
            return Address + "/" + Prefix;
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