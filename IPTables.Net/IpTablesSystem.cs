using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using SystemInteract;
using IPTables.Net.Iptables;
using IPTables.Net.Iptables.Adapter;
using IPTables.Net.Iptables.Adapter.Client;
using IPTables.Net.Iptables.IpSet.Adapter;
using System.Runtime.CompilerServices;
using IPTables.Net.Exceptions;

[assembly: InternalsVisibleTo("IPTables.Net.Tests")]
[assembly: InternalsVisibleTo("IPTables.Net.TestFramework")]

namespace IPTables.Net
{
    /// <summary>
    /// A class to act as the core controller for the IPTables system being manipulated
    /// </summary>
    public class IpTablesSystem
    {
        private readonly ISystemFactory _system;
        private readonly IpSetBinaryAdapter _setAdapter;
        private IIPTablesAdapter _tableAdapter;

        public ISystemFactory System => _system;

        public IpSetBinaryAdapter SetAdapter => _setAdapter;

        public IIPTablesAdapter TableAdapter => _tableAdapter;

        public IpTablesSystem(ISystemFactory system, IIPTablesAdapter tableAdapter,
            IpSetBinaryAdapter setAdapter = null)
        {
            _system = system;
            _tableAdapter = tableAdapter;
            _setAdapter = setAdapter;
        }

        public List<string> GetChainNames(IIPTablesAdapterClient client, string table, int ipVersion)
        {
            var adapter = client as IIPTablesAdapterClient;
            return adapter.GetChains(table);
        }

        public IIPTablesAdapterClient GetTableAdapter(int version)
        {
            return _tableAdapter.GetClient(this, version);
        }

        public void DeleteChain(IIPTablesAdapterClient client, string name, string table = "filter", int ipVersion = 4,
            bool flush = false)
        {
            client.DeleteChain(table, name, flush);
        }

        public IpTablesChain AddChain(IIPTablesAdapterClient client, string name, string table = "filter",
            int ipVersion = 4)
        {
            client.AddChain(table, name);

            return new IpTablesChain(table, name, ipVersion, this, new List<IpTablesRule>());
        }

        public List<string> GetChainNames(string table, int ipVersion)
        {
            using (var client = GetTableAdapter(ipVersion))
            {
                return GetChainNames(client, table, ipVersion);
            }
        }


        public IpTablesChain AddChain(IIPTablesAdapterClient client, IpTablesChain chain, bool addRules = false)
        {
            client.AddChain(chain.Table, chain.Name);

            if (addRules)
                foreach (var r in chain.Rules)
                    r.AddRule();
            else
                chain = new IpTablesChain(chain.Table, chain.Name, chain.IpVersion, chain.System);

            return chain;
        }


        public void DeleteChain(string name, string table = "filter", int ipVersion = 4, bool flush = false)
        {
            using (var client = GetTableAdapter(ipVersion))
            {
                DeleteChain(client, name, table, ipVersion, flush);
            }
        }

        public IpTablesChain AddChain(string name, string table = "filter", int ipVersion = 4)
        {
            using (var client = GetTableAdapter(ipVersion))
            {
                return AddChain(client, name, table, ipVersion);
            }
        }

        public IpTablesChain AddChain(IpTablesChain chain, bool addRules = false)
        {
            return AddChain(chain.Name, chain.Table, chain.IpVersion);
        }


        public IpTablesChainSet GetRules(string table, int ipVersion)
        {
            using (var client = GetTableAdapter(ipVersion))
            {
                return GetRules(client, table);
            }
        }

        public IEnumerable<IpTablesRule> GetRules(string table, string chain, int ipVersion)
        {
            using (var client = GetTableAdapter(ipVersion))
            {
                return GetRules(client, table, chain);
            }
        }

        public IEnumerable<IpTablesChain> GetChains(string table, int ipVersion)
        {
            using (var client = GetTableAdapter(ipVersion))
            {
                return GetChains(client, table);
            }
        }


        public IpTablesChain GetChain(string table, string chain, int ipVersion)
        {
            using (var client = GetTableAdapter(ipVersion))
            {
                return GetChain(client, table, chain);
            }
        }

        public IpTablesChain GetChain(IIPTablesAdapterClient client, string table, string chain)
        {
            var tableRules = GetRules(client, table);
            if (tableRules == null) throw new IpTablesNetException("Unable to get a chainset for table: " + table);
            return tableRules.GetChainOrDefault(chain, table);
        }


        public IpTablesChainSet GetRules(IIPTablesAdapterClient client, string table)
        {
            return client.ListRules(table);
        }

        public IEnumerable<IpTablesRule> GetRules(IIPTablesAdapterClient client, string table, string chain)
        {
            return GetChain(client, table, chain).Rules;
        }

        public IEnumerable<IpTablesChain> GetChains(IIPTablesAdapterClient client, string table)
        {
            return GetRules(client, table).Chains;
        }
    }
}