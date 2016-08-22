using System;
using System.Collections.Generic;
using SystemInteract;
using IPTables.Net.Conntrack;
using IPTables.Net.Exceptions;
using IPTables.Net.Iptables;
using IPTables.Net.Iptables.Adapter;
using IPTables.Net.Iptables.Adapter.Client;
using IPTables.Net.Iptables.IpSet.Adapter;

namespace IPTables.Net.Netfilter
{
    public class NetfilterSystem
    {
        private readonly ISystemFactory _system;
        private readonly IpSetBinaryAdapter _setAdapter;
        private INetfilterAdapter _tableAdapter;

        public NetfilterSystem(ISystemFactory system, INetfilterAdapter tableAdapter, IpSetBinaryAdapter setAdapter = null)
        {
            _system = system;
            _tableAdapter = tableAdapter;
            if (setAdapter == null)
            {
                setAdapter = new IpSetBinaryAdapter(system);
            }
            _setAdapter = setAdapter;
        }

        public ISystemFactory System
        {
            get { return _system; }
        }

        public INetfilterAdapterClient GetTableAdapter(int version)
        {
            return _tableAdapter.GetClient(this, 4);
        }

        public IpSetBinaryAdapter SetAdapter
        {
            get { return _setAdapter; }
        }

        public INetfilterChainSet GetRules(INetfilterAdapterClient client, string table, int ipVersion)
        {
            return client.ListRules(table);
        }

        public IEnumerable<INetfilterRule> GetRules(INetfilterAdapterClient client, string table, string chain, int ipVersion)
        {
            return GetChain(client, table, chain, ipVersion).Rules;
        }

        public IEnumerable<INetfilterChain> GetChains(INetfilterAdapterClient client, string table, int ipVersion)
        {
            return GetRules(client, table, ipVersion).Chains;
        }


        public INetfilterChainSet GetRules(string table, int ipVersion)
        {
            using (var client = GetTableAdapter(ipVersion))
            {
                return GetRules(client, table, ipVersion);
            }
        }

        public IEnumerable<INetfilterRule> GetRules(string table, string chain, int ipVersion)
        {
            using (var client = GetTableAdapter(ipVersion))
            {
                return GetRules(client, table, chain, ipVersion);
            }
        }

        public IEnumerable<INetfilterChain> GetChains(string table, int ipVersion)
        {
            using (var client = GetTableAdapter(ipVersion))
            {
                return GetChains(client, table, ipVersion);
            }
        }


        public INetfilterChain GetChain(string table, string chain, int ipVersion)
        {
            using (var client = GetTableAdapter(ipVersion))
            {
                return GetChain(client, table, chain, ipVersion);
            }
        }

        public INetfilterChain GetChain(INetfilterAdapterClient client, string table, string chain, int ipVersion)
        {
            INetfilterChainSet tableRules = GetRules(client, table, ipVersion);
            if (tableRules == null)
            {
                throw new IpTablesNetException("Unable to get a chainset for table: "+table);
            }
            return tableRules.GetChainOrDefault(chain, table);
        }


        public void DeleteChain(INetfilterAdapterClient client, string name, string table = "filter", int ipVersion = 4, bool flush = false)
        {
            client.DeleteChain(table, name, flush);
        }

        public IpTablesChain AddChain(INetfilterAdapterClient client, String name, String table = "filter", int ipVersion = 4)
        {
            client.AddChain(table, name);

            return new IpTablesChain(table, name, ipVersion, this, new List<IpTablesRule>());
        }

        public IpTablesChain AddChain(INetfilterAdapterClient client, IpTablesChain chain, bool addRules = false)
        {
            client.AddChain(chain.Table, chain.Name);

            if (addRules)
            {
                foreach (IpTablesRule r in chain.Rules)
                {
                    r.AddRule();
                }
            }
            else
            {
                chain = new IpTablesChain(chain.Table,chain.Name, chain.IpVersion, chain.System);
            }

            return chain;
        }

        
        public void DeleteChain(string name, string table = "filter", int ipVersion = 4, bool flush = false)
        {
            using (var client = GetTableAdapter(ipVersion))
            {
                DeleteChain(client, name, table, ipVersion, flush);
            }
        }

        public IpTablesChain AddChain(String name, String table = "filter", int ipVersion = 4)
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
    }
}