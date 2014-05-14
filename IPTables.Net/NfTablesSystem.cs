using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using SystemInteract;
using IPTables.Net.Iptables;
using IPTables.Net.Iptables.Adapter;
using IPTables.Net.Netfilter;
using IPTables.Net.NfTables;
using IPTables.Net.NfTables.Adapter;

namespace IPTables.Net
{
    public class NfTablesSystem: NetfilterSystem
    {
        public NfTablesSystem(ISystemFactory system, INfTablesAdapter adapter)
            : base(system, adapter)
        {
        }

        public IEnumerable<NfTablesChain> GetChains(String table)
        {
            return base.GetChains(table).Cast<NfTablesChain>();
        }
    }
}
