using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace IPTables.Net.Iptables.IpSet
{
    class IpSetEntryKeyComparer: IEqualityComparer<IpSetEntry>
    {
        public bool Equals(IpSetEntry x, IpSetEntry y)
        {
            Debug.Assert(x != null, nameof(x) + " != null");
            bool ret = x.KeyEquals(y);
            return ret;
        }
        
        public int GetHashCode(IpSetEntry obj)
        {
            unchecked
            {
                int hashCode = obj.Cidr.GetHashCode();
                hashCode = (hashCode * 397) ^ (obj.Protocol != null ? obj.Protocol.GetHashCode() : 0);
                hashCode = (hashCode * 397) ^ obj.Port.GetHashCode();
                hashCode = (hashCode * 397) ^ (obj.Mac != null ? obj.Mac.GetHashCode() : 0);
                hashCode = (hashCode * 397) ^ obj.Timeout.GetHashCode();
                return hashCode;
            }
        }

        public static IEqualityComparer<IpSetEntry> Instance = new IpSetEntryKeyComparer();
    }
}
