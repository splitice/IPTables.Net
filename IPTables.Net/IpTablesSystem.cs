using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using SystemInteract;
using IPTables.Net.Iptables;
using IPTables.Net.Iptables.Adapter;
using IPTables.Net.Netfilter;

namespace IPTables.Net
{
    public class IpTablesSystem: NetfilterSystem
    {
        public IpTablesSystem(ISystemFactory system, IIPTablesAdapter adapter) : base(system, adapter)
        {
        }

        public IEnumerable<IpTablesChain> GetChains(String table)
        {
            return base.GetChains(table).Cast<IpTablesChain>();
        }
    }
}
