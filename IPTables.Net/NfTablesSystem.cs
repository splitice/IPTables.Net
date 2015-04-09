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
    /// <summary>
    /// A class to act as the core controller for the IPTables system being manipulated
    /// 
    /// This is not yet complete. DO NOT USE. Pull Requests Welcome.
    /// </summary>
    public class NfTablesSystem: NetfilterSystem
    {
        public NfTablesSystem(ISystemFactory system, INfTablesAdapter adapter)
            : base(system, adapter)
        {
        }

        public new IEnumerable<NfTablesChain> GetChains(String table, int ipVersion)
        {
            return base.GetChains(table, ipVersion).Cast<NfTablesChain>();
        }
    }
}
