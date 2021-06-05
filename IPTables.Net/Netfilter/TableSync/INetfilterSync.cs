using System;
using System.Collections.Generic;
using IPTables.Net.Iptables;
using IPTables.Net.Iptables.Adapter.Client;

namespace IPTables.Net.Netfilter.TableSync
{
    public interface INetfilterSync
    {
        void SyncChainRules(IIPTablesAdapterClient client, IEnumerable<IpTablesRule> with, IpTablesChain currentChain);
        IEnumerable<string> TableOrder { get; }
    }
}