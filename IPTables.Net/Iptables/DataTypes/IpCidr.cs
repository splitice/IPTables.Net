using System;
using System.Net;
using System.Net.Sockets;
using System.Numerics;
using IPTables.Net.Exceptions;
using IPTables.Net.Supporting;

namespace IPTables.Net.Iptables.DataTypes
{
    extern alias IPNetwork2;

    public struct IpCidr : IEquatable<IpCidr>, IComparable<IpCidr>, IComparable
    {
        public static IpCidr Any = new IpCidr(IPAddress.Any, 0);

        public readonly IPAddress Address;
        public readonly uint Prefix;

        public IpCidr(IPAddress address, uint prefix)
        {
            ArgumentNullException.ThrowIfNull(address);
            if (prefix > (address.AddressFamily == AddressFamily.InterNetworkV6 ? 128u : 32u))
                throw new ArgumentOutOfRangeException(nameof(prefix));
            Address = address;
            Prefix = prefix;
        }

        public IpCidr(IPAddress address)
        {
            Address = address;
            Prefix = address.AddressFamily == AddressFamily.InterNetworkV6 ? (uint) 128 : 32;
        }

        public BigInteger Addresses
        {
            get
            {
                var max = Address.AddressFamily == AddressFamily.InterNetworkV6 ? 128 : 32;
                return BigInteger.Pow(2, max - (int) Prefix);
            }
        }

        public IPNetwork2::System.Net.IPNetwork2 GetIPNetwork()
        {
            return IPNetwork2::System.Net.IPNetwork2.Parse(Address, IPNetwork2::System.Net.IPNetwork2.ToNetmask((byte) Prefix, Address.AddressFamily));
        }

        public bool Equals(IpCidr other)
        {
            return Equals(Address, other.Address) && Prefix == other.Prefix;
        }

        public static IpCidr Parse(string cidr)
        {
            var p = cidr.Split(new[] {'/'});
            if (p.Length > 2) throw new IpTablesNetException("Invalid CIDR components");
            IPAddress ip;
            try
            {
                ip = IPAddress.Parse(p[0]);
            }
            catch (Exception ex)
            {
                throw new IpTablesNetException("Invalid IP Address: " + p[0], ex);
            }

            if (p.Length == 1) return new IpCidr(ip);


            try
            {
                var cidrN = uint.Parse(p[1]);
                if (ip.AddressFamily == AddressFamily.InterNetwork)
                {
                    if (cidrN > 32) throw new IpTablesNetException("Invalid CIDR number (>32) number: " + cidrN);
                }
                else if (ip.AddressFamily == AddressFamily.InterNetworkV6)
                {
                    if (cidrN > 128) throw new IpTablesNetException("Invalid CIDR number (>128) number: " + cidrN);
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
            if (Prefix == 32 && Address.AddressFamily == AddressFamily.InterNetwork || Prefix == 128)
                return Address.ToString();
            return Address + "/" + Prefix;
        }

        public int CompareTo(object obj)
        {
            if (obj is IpCidr) return CompareTo((IpCidr) obj);
            return 0;
        }

        public bool Contains(IpCidr cidr)
        {
            return Address.AddressFamily == cidr.Address.AddressFamily && Prefix <= cidr.Prefix && Contains(cidr.Address);
        }

        public bool Contains(IPAddress addr)
        {
            if (Address.AddressFamily != addr.AddressFamily) return false;
            var outer = Address.GetAddressBytes(); var inner = addr.GetAddressBytes();
            for (int bit = 0; bit < Prefix; bit++)
                if ((outer[bit / 8] & (128 >> (bit % 8))) != (inner[bit / 8] & (128 >> (bit % 8)))) return false;
            return true;
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
            _ = new IpCidr(findAddress, u); // Validate before changing address bits.
            var bytes = findAddress.GetAddressBytes();
            for (int bit = (int)u; bit < bytes.Length * 8; bit++) bytes[bit / 8] &= (byte)~(128 >> (bit % 8));
            var network = findAddress.AddressFamily == AddressFamily.InterNetworkV6
                ? new IPAddress(bytes, findAddress.ScopeId)
                : new IPAddress(bytes);
            return new IpCidr(network, u);
        }
    }
}
