using System;
using System.Collections.Generic;
using System.Linq;
using IPTables.Net.Netfilter;

namespace IPTables.Net.Iptables
{
    public class IpTablesChainSet: NetfilterChainSet<IpTablesChain, IpTablesRule>
    {
        public void AddDefaultChains(NetfilterSystem system)
        {
            _chains.Add(new IpTablesChain("filter", "INPUT", system));
            _chains.Add(new IpTablesChain("filter", "FORWARD", system));
            _chains.Add(new IpTablesChain("filter", "OUTPUT", system));

            _chains.Add(new IpTablesChain("mangle", "INPUT", system));
            _chains.Add(new IpTablesChain("mangle", "FORWARD", system));
            _chains.Add(new IpTablesChain("mangle", "OUTPUT", system));
            _chains.Add(new IpTablesChain("mangle", "PREROUTING", system));
            _chains.Add(new IpTablesChain("mangle", "POSTROUTING", system));

            _chains.Add(new IpTablesChain("nat", "PREROUTING", system));
            _chains.Add(new IpTablesChain("nat", "POSTROUTING", system));
            _chains.Add(new IpTablesChain("nat", "OUTPUT", system));
        }
        protected override IpTablesChain CreateChain(string tableName, string chainName, NetfilterSystem system)
        {
            return new IpTablesChain(tableName, chainName, system);
        }
    }
}