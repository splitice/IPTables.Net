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

        public bool HasChain(String name, String table)
        {
            return _chains.FirstOrDefault((a) => a.Name == name && a.Table == table) != null;
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


        public IpTablesChain GetChainOrAdd(string chainName, string tableName)
        {
            throw new NotImplementedException();
        }

        public IpTablesChain GetChainOrAdd(IpTablesChain chainName)
        {
            throw new NotImplementedException();
        }

        public void AddRule(IpTablesRule rule)
        {
            throw new NotImplementedException();
        }

        public List<IpTablesRule> GetChainOrDefault(string chain, string table)
        {
            throw new NotImplementedException();
        }
    }
}
