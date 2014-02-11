using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace IPTables.Net.Iptables
{
    public class IpTablesChainSet
    {
        private readonly HashSet<IpTablesChain> _chains = new HashSet<IpTablesChain>();

        public HashSet<IpTablesChain> Chains
        {
            get
            {
                return _chains;
            }
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

            if (_chains.FirstOrDefault((a) => a.Name == chain.Name && a.Table == chain.Table) != null)
            {
                throw new Exception("Chain Set already contains a chain with the same name in this table");
            }

            _chains.Add(chain);
        }


        public IpTablesChain GetChainOrAdd(string chainName, string tableName, IpTablesSystem system)
        {
            var chain = GetChainOrDefault(chainName, tableName);

            if (chain != null)
                return chain;

            return AddChain(chainName, tableName, system);
        }

        private IpTablesChain AddChain(string chainName, string tableName, IpTablesSystem system)
        {
            IpTablesChain chain = new IpTablesChain(tableName, chainName, system);
            AddChain(chain);
            return chain;
        }

        public IpTablesChain GetChainOrAdd(IpTablesChain chain)
        {
            var chainFound = GetChainOrDefault(chain.Name, chain.Table);

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
            var chain = GetChainOrAdd(rule.Chain);
            chain.Rules.Add(rule);
        }

        public IpTablesChain GetChainOrDefault(string chain, string table)
        {
            return _chains.FirstOrDefault((a) => a.Name == chain && a.Table == table);
        }
    }
}
