using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace IPTables.Net.Iptables.IpSet
{
    class IpSetEntryKeyComparer: IEqualityComparer<IpSetEntry>
    {
        public bool Equals(IpSetEntry x, IpSetEntry y)
        {
            return x.KeyEquals(y);
        }

        public int GetHashCode(IpSetEntry obj)
        {
            return obj.GetHashCode();
        }
    }
}
