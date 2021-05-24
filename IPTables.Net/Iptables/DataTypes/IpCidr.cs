using System;
using System.Net;
using System.Net.Sockets;
using System.Numerics;
using IPTables.Net.Exceptions;
using IPTables.Net.Supporting;

namespace IPTables.Net.Iptables.DataTypes
{
    public struct IpCidr : IEquatable<IpCidr>, IComparable<IpCidr>, IComparable
    {
        public static IpCidr Any = new IpCidr(IPAddress.Any, 0);

        public readonly IPAddress Address;
        public readonly uint Prefix;

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

        public BigInteger Addresses
        {
            get
            {
                int max = (Address.AddressFamily == AddressFamily.InterNetworkV6) ? 128 : 32;
                return BigInteger.Pow(2, max - (int)Prefix);
            }
        }

        public IPNetwork GetIPNetwork()
        {
            return IPNetwork.Parse(Address, IPNetwork.ToNetmask((byte)Prefix, Address.AddressFamily));
        }

        public bool Equals(IpCidr other)
        {
            return Equals(Address, other.Address) && Prefix == other.Prefix;
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

        public int CompareTo(IpCidr other)
        {
            var result = Address.AddressFamily.CompareTo(other.Address.AddressFamily);
            if (result != 0)
                return result;

            var xBytes = Address.GetAddressBytes();
            var yBytes = other.Address.GetAddressBytes();

            var octets = Math.Min(xBytes.Length, yBytes.Length);
            for (var i = 0; i < octets; i++)
            {
                var octetResult = xBytes[i].CompareTo(yBytes[i]);
                if (octetResult != 0)
                    return octetResult;
            }

            return Prefix.CompareTo(other.Prefix);
        }

        public override string ToString()
        {
            if ((Prefix == 32 && Address.AddressFamily == AddressFamily.InterNetwork) || Prefix == 128)
            {
                return Address.ToString();
            }
            return Address + "/" + Prefix;
        }

        public int CompareTo(object obj)
        {
            if (obj is IpCidr)
            {
                return CompareTo((IpCidr) obj);
            }
            return 0;
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

        public bool Contains(IPAddress addr)
        {
            var thisNetwork = GetIPNetwork();
            var innerNetwork = addr.ToInt();
            if (thisNetwork.Network.ToInt() <= innerNetwork &&
                thisNetwork.Broadcast.ToInt() >= innerNetwork)
            {
                return true;
            }

            return false;
        }

        public override bool Equals(object obj)
        {
            return obj is IpCidr other && Equals(other);
        }

        public override int GetHashCode()
        {
            return HashCode.Combine(Address, Prefix);
        }

        public static IpCidr NewRebase(IPAddress findAddress, uint u)
        {
            if (findAddress.AddressFamily == AddressFamily.InterNetwork)
            {
                if (u == 32)
                {
                    return new IpCidr(findAddress, u);
                }
                var iAddr = findAddress.ToInt() & ~(long)(Math.Pow(2, 32 - u) - 1);
                var ip = IPAddressExtension.ToAddr(iAddr);
                return new IpCidr(ip, u);
            }
            else
            {
                if (u == 128)
                {
                    return new IpCidr(findAddress, u);
                }
                var ipNet = IPNetwork.Parse(findAddress.ToString(), (byte) u);
                return new IpCidr(ipNet.Network, u);
            }
        }
    }
}