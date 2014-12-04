using System;
using System.Collections.Generic;
using SystemInteract;
using IPTables.Net.Iptables;
using IPTables.Net.Iptables.Adapter;
using IPTables.Net.Iptables.Adapter.Client;

namespace IPTables.Net.Netfilter
{
    public class NetfilterSystem
    {
        private readonly ISystemFactory _system;
        private readonly INetfilterAdapterClient _adapter;

        public NetfilterSystem(ISystemFactory system, INetfilterAdapter adapter)
        {
            _system = system;
            _adapter = adapter.GetClient(this);
        }

        public ISystemFactory System
        {
            get { return _system; }
        }

        public INetfilterAdapterClient Adapter
        {
            get { return _adapter; }
        }

        public INetfilterChainSet GetRules(string table)
        {
            return _adapter.ListRules(table);
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
                throw new Exception("Unable to get a chainset for table: "+table);
            }
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