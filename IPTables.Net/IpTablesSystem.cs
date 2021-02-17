using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using SystemInteract;
using IPTables.Net.Iptables;
using IPTables.Net.Iptables.Adapter;
using IPTables.Net.Iptables.Adapter.Client;
using IPTables.Net.Iptables.IpSet.Adapter;
using IPTables.Net.Netfilter;
using System.Runtime.CompilerServices;

[assembly: InternalsVisibleTo("IPTables.Net.Tests")]
[assembly: InternalsVisibleTo("IPTables.Net.TestFramework")]
namespace IPTables.Net
{
    /// <summary>
    /// A class to act as the core controller for the IPTables system being manipulated
    /// </summary>
    public class IpTablesSystem: NetfilterSystem
    {
        public IpTablesSystem(ISystemFactory system, IIPTablesAdapter tableAdapter, IpSetBinaryAdapter setAdapter = null)
            : base(system, tableAdapter, setAdapter)
        {
        }

        public new IEnumerable<IpTablesChain> GetChains(String table, int ipVersion)
        {
            return base.GetChains(table, ipVersion).Cast<IpTablesChain>();
        }

        public IEnumerable<IpTablesChain> GetChains(INetfilterAdapterClient client, String table, int ipVersion)
        {
            return base.GetChains(client, table).Cast<IpTablesChain>();
        }

        public List<String> GetChainNames(INetfilterAdapterClient client, String table, int ipVersion)
        {
            var adapter = client as IIPTablesAdapterClient;
            return adapter.GetChains(table);
        }

        public List<String> GetChainNames(String table, int ipVersion)
        {
            using (var client = GetTableAdapter(ipVersion))
            {
                return GetChainNames(client, table, ipVersion);
            }
        }
    }
}
