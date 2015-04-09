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
        private readonly INetfilterAdapterClient _tableAdapter4;
        private readonly INetfilterAdapterClient _tableAdapter6;
        private readonly IpSetBinaryAdapter _setAdapter;

        public NetfilterSystem(ISystemFactory system, INetfilterAdapter tableAdapter, IpSetBinaryAdapter setAdapter = null)
        {
            _system = system;
            _tableAdapter4 = tableAdapter == null ? null : tableAdapter.GetClient(this,4);
            _tableAdapter6 = tableAdapter == null ? null : tableAdapter.GetClient(this,6);
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
            return version == 4 ? _tableAdapter4 : _tableAdapter6;
        }

        public IpSetBinaryAdapter SetAdapter
        {
            get { return _setAdapter; }
        }

        public INetfilterChainSet GetRules(string table, int ipVersion)
        {
            return GetTableAdapter(ipVersion).ListRules(table);
        }

        public IEnumerable<INetfilterRule> GetRules(string table, string chain, int ipVersion)
        {
            return GetChain(table, chain, ipVersion).Rules;
        }

        public IEnumerable<INetfilterChain> GetChains(string table, int ipVersion)
        {
            return GetRules(table, ipVersion).Chains;
        }


        public INetfilterChain GetChain(string table, string chain, int ipVersion)
        {
            INetfilterChainSet tableRules = GetRules(table, ipVersion);
            if (tableRules == null)
            {
                throw new IpTablesNetException("Unable to get a chainset for table: "+table);
            }
            return tableRules.GetChainOrDefault(chain, table);
        }


        public void DeleteChain(string name, string table = "filter", int ipVersion = 4, bool flush = false)
        {
            GetTableAdapter(ipVersion).DeleteChain(table, name, flush);
        }

        public IpTablesChain AddChain(String name, String table = "filter", int ipVersion = 4)
        {
            GetTableAdapter(ipVersion).AddChain(table, name);

            return new IpTablesChain(table, name, ipVersion, this, new List<IpTablesRule>());
        }

        public IpTablesChain AddChain(IpTablesChain chain, bool addRules = false)
        {
            GetTableAdapter(chain.IpVersion).AddChain(chain.Table, chain.Name);

            if (addRules)
            {
                foreach (IpTablesRule r in chain.Rules)
                {
                    r.AddRule();
                }
            }
            else
            {
                chain = new IpTablesChain(chain.Table,chain.Name, chain.IpVersion,chain.System);
            }

            return chain;
        }
    }
}