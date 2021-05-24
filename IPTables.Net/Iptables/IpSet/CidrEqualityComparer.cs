using System.Collections.Generic;

namespace IPTables.Net.Iptables.IpSet
{
    public class CidrEqualityComparer : IEqualityComparer<IpSetEntry>
    {
        public bool Equals(IpSetEntry x, IpSetEntry y)
        {
            if (ReferenceEquals(x, y)) return true;
            if (ReferenceEquals(x, null)) return false;
            if (ReferenceEquals(y, null)) return false;
            if (x.GetType() != y.GetType()) return false;
            return x.Cidr.Equals(y.Cidr);
        }

        public int GetHashCode(IpSetEntry obj)
        {
            return obj.Cidr.GetHashCode();
        }
    }
}