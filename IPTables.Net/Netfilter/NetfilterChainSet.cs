using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using IPTables.Net.Iptables;

namespace IPTables.Net.Netfilter
{
    public abstract class NetfilterChainSet<T, T2>
        where T : class, INetfilterChain
        where T2 : class, INetfilterRule
    {
        protected readonly HashSet<T> _chains = new HashSet<T>();

        public HashSet<T> Chains
        {
            get { return _chains; }
        }

        public bool HasChain(String chain, String table)
        {
            return GetChainOrDefault(chain, table) != null;
        }

        public void AddChain(T chain)
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

        protected abstract T CreateChain(String tableName, String chainName, NetfilterSystem system);

        public T GetChainOrAdd(string chainName, string tableName, NetfilterSystem system)
        {
            T chain = GetChainOrDefault(chainName, tableName);

            if (chain != null)
                return chain;

            return AddChain(chainName, tableName, system);
        }

        private T AddChain(string chainName, string tableName, NetfilterSystem system)
        {
            var chain = CreateChain(tableName, chainName, system);
            AddChain(chain);
            return chain;
        }

        public T GetChainOrAdd(T chain)
        {
            T chainFound = GetChainOrDefault(chain.Name, chain.Table);

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

        public void AddRule(T2 rule)
        {
            T chain = GetChainOrAdd(rule.Chain as T);
            chain.AddRule(rule);
        }

        public T GetChainOrDefault(string chain, string table)
        {
            return _chains.FirstOrDefault(a => a.Name == chain && a.Table == table);
        }
    }
}
