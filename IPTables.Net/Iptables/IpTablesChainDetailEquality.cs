using System;
using System.Collections.Generic;
using System.Text;

namespace IPTables.Net.Iptables
{
    public class IpTablesChainDetailEquality: IEqualityComparer<IpTablesChain>
    {
        public bool Equals(IpTablesChain x, IpTablesChain y)
        {
            if (x == y) return true;
            if (x == null || y == null) return false;
            return x.Name == y.Name && x.Table == y.Table && x.IpVersion == y.IpVersion;
        }

        public int GetHashCode(IpTablesChain obj)
        {
            return obj.Name.GetHashCode();
        }
    }
}
