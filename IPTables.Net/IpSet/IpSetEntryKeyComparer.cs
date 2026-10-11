using System.Collections.Generic;
using System.Diagnostics;

namespace IPTables.Net.IpSet
{
    internal class IpSetEntryKeyComparer : IEqualityComparer<IpSetEntry>
    {
        public bool Equals(IpSetEntry x, IpSetEntry y)
        {
            return ReferenceEquals(x, y) || (x != null && y != null && x.KeyEquals(y));
        }

        public int GetHashCode(IpSetEntry obj)
        {
            unchecked
            {
                var hashCode = obj.Cidr.GetHashCode();
                hashCode = (hashCode * 397) ^ (obj.Protocol != null ? obj.Protocol.GetHashCode() : 0);
                hashCode = (hashCode * 397) ^ obj.Port.GetHashCode();
                hashCode = (hashCode * 397) ^ (obj.Mac != null ? obj.Mac.GetHashCode() : 0);
                hashCode = (hashCode * 397) ^ obj.Cidr2.GetHashCode();
                return hashCode;
            }
        }

        public static IEqualityComparer<IpSetEntry> Instance = new IpSetEntryKeyComparer();
    }
}