using System;
using System.Collections.Generic;
using SystemInteract;
using IPTables.Net.Iptables;
using IPTables.Net.Iptables.Adapter;
using IPTables.Net.Iptables.Adapter.Client;

namespace IPTables.Net
{
    public class IpTablesSystem
    {
        private readonly ISystemFactory _system;
        private readonly IIPTablesAdapterClient _adapter;

        public IpTablesSystem(ISystemFactory system, IIPTablesAdapter adapter)
        {
            _system = system;
            _adapter = adapter.GetClient(this);
        }

        public ISystemFactory System
        {
            get { return _system; }
        }

        public IIPTablesAdapterClient Adapter
        {
            get { return _adapter; }
        }

        public IpTablesChainSet GetRules(string table)
        {
            return _adapter.ListRules(table);
        }

        public List<IpTablesRule> GetRules(string table, string chain)
        {
            return GetChain(table, chain).Rules;
        }

        public IEnumerable<IpTablesChain> GetChains(string table)
        {
            return GetRules(table).Chains;
        }


        public IpTablesChain GetChain(string table, string chain)
        {
            IpTablesChainSet tableRules = GetRules(table);
            return tableRules.GetChainOrDefault(chain, table);
        }


        public void DeleteChain(string name, string table = "filter", bool flush = false)
        {
            _adapter.DeleteChain(table, name, flush);
        }

        public IpTablesChain AddChain(String name, String table = "filter")
        {
            _adapter.AddChain(table, name);

            return new IpTablesChain(table, name, this, new List<IpTablesRule>());
        }

        public IpTablesChain AddChain(IpTablesChain chain, bool addRules = false)
        {
            _adapter.AddChain(chain.Table,chain.Name);

            if (addRules)
            {
                foreach (IpTablesRule r in chain.Rules)
                {
                    r.Add();
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