using System;
using System.Collections.Generic;
using System.Linq;

namespace IPTables.Net.Iptables
{
    public class IpTablesChainSet
    {
        private readonly HashSet<IpTablesChain> _chains = new HashSet<IpTablesChain>();

        public HashSet<IpTablesChain> Chains
        {
            get { return _chains; }
        }

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

        public bool HasChain(String chain, String table)
        {
            return GetChainOrDefault(chain, table) != null;
        }

        public void AddChain(IpTablesChain chain)
        {
            if (_chains.Contains(chain))
            {
                throw new Exception("Chain Set already contains this chain");
            }

            if (_chains.FirstOrDefault(a => a.Name == chain.Name && a.Table == chain.Table) != null)
            {
                throw new Exception("Chain Set already contains a chain with the same name in this table");
            }

            _chains.Add(chain);
        }


        public IpTablesChain GetChainOrAdd(string chainName, string tableName, NetfilterSystem system)
        {
            IpTablesChain chain = GetChainOrDefault(chainName, tableName);

            if (chain != null)
                return chain;

            return AddChain(chainName, tableName, system);
        }

        private IpTablesChain AddChain(string chainName, string tableName, NetfilterSystem system)
        {
            var chain = new IpTablesChain(tableName, chainName, system);
            AddChain(chain);
            return chain;
        }

        public IpTablesChain GetChainOrAdd(IpTablesChain chain)
        {
            IpTablesChain chainFound = GetChainOrDefault(chain.Name, chain.Table);

            if (chainFound == null)
            {
                AddChain(chain);
            }
            else
            {
                return chainFound;
            }


            return chain;
        }

        public void AddRule(IpTablesRule rule)
        {
            IpTablesChain chain = GetChainOrAdd(rule.Chain);
            chain.Rules.Add(rule);
        }

        public IpTablesChain GetChainOrDefault(string chain, string table)
        {
            return _chains.FirstOrDefault(a => a.Name == chain && a.Table == table);
        }
    }
}