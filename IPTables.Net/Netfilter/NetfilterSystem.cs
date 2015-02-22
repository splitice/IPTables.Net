using System;
using System.Collections.Generic;
using SystemInteract;
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
        private readonly INetfilterAdapterClient _tableAdapter;
        private readonly IpSetBinaryAdapter _setAdapter;

        public NetfilterSystem(ISystemFactory system, INetfilterAdapter tableAdapter, IpSetBinaryAdapter setAdapter = null)
        {
            _system = system;
            _tableAdapter = tableAdapter == null ? null : tableAdapter.GetClient(this);
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

        public INetfilterAdapterClient TableAdapter
        {
            get { return _tableAdapter; }
        }

        public IpSetBinaryAdapter SetAdapter
        {
            get { return _setAdapter; }
        }

        public INetfilterChainSet GetRules(string table)
        {
            return _tableAdapter.ListRules(table);
        }

        public IEnumerable<INetfilterRule> GetRules(string table, string chain)
        {
            return GetChain(table, chain).Rules;
        }

        public IEnumerable<INetfilterChain> GetChains(string table)
        {
            return GetRules(table).Chains;
        }


        public INetfilterChain GetChain(string table, string chain)
        {
            INetfilterChainSet tableRules = GetRules(table);
            if (tableRules == null)
            {
                throw new IpTablesNetException("Unable to get a chainset for table: "+table);
            }
            return tableRules.GetChainOrDefault(chain, table);
        }


        public void DeleteChain(string name, string table = "filter", bool flush = false)
        {
            _tableAdapter.DeleteChain(table, name, flush);
        }

        public IpTablesChain AddChain(String name, String table = "filter")
        {
            _tableAdapter.AddChain(table, name);

            return new IpTablesChain(table, name, this, new List<IpTablesRule>());
        }

        public IpTablesChain AddChain(IpTablesChain chain, bool addRules = false)
        {
            _tableAdapter.AddChain(chain.Table,chain.Name);

            if (addRules)
            {
                foreach (IpTablesRule r in chain.Rules)
                {
                    r.AddRule();
                }
            }
            else
            {
                chain = new IpTablesChain(chain.Table,chain.Name,chain.System);
            }

            return chain;
        }
    }
}