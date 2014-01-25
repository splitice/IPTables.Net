﻿using System;
using System.Net;

namespace IPTables.Net.DataTypes
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

        public static IpCidr Parse(String cidr)
        {
            bool not = false;
            cidr = cidr.Trim();
            if (cidr[0] == '!')
            {
                not = true;
                cidr = cidr.Substring(1).TrimStart();
            }
            string[] p = cidr.Split(new[] {'/'});
            IPAddress ip;
            try
            {
                ip = IPAddress.Parse(p[0]);
            }
            catch (Exception)
            {
                return IpCidr.Any;
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
                return IpCidr.Any;
            }
        }

        public bool Equals(IpCidr other)
        {
            return other.Address.Equals(Address) && other.Cidr == Cidr;
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
    }
}