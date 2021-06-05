using System.Collections.Generic;
using IPTables.Net.Iptables.Adapter.Client;

namespace IPTables.Net.Iptables.TableSync
{
    public interface IRuleSync
    {
        void SyncChainRules(IIPTablesAdapterClient client, IEnumerable<IpTablesRule> with, IpTablesChain currentChain);
        IEnumerable<string> TableOrder { get; }
    }
}