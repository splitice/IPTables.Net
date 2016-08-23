using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using IPTables.Net.Exceptions;
using IPTables.Net.Netfilter;

namespace IPTables.Net.Iptables
{
    public class IpTablesChainSet : NetfilterChainSet<IpTablesChain, IpTablesRule>, IEnumerable<IpTablesChain>
    {
        private int _ipVersion;

        public int IpVersion
        {
            get { return _ipVersion; }
        }

        public IEnumerable<IpTablesChain> Chains
        {
            get { return _chains; }
        }

        public IpTablesChainSet(int ipVersion)
        {
            _ipVersion = ipVersion;
        }

        public void AddDefaultChains(NetfilterSystem system)
        {
            foreach (var tablePair in IPTablesTables.Tables)
            {
                foreach (var chain in tablePair.Value)
                {
                    _chains.Add(new IpTablesChain(tablePair.Key, chain, _ipVersion, system));
                }
            }
        }
        protected override IpTablesChain CreateChain(string tableName, string chainName, NetfilterSystem system)
        {
            return new IpTablesChain(tableName, chainName, _ipVersion, system);
        }

        public IpTablesChain AddChain(String name, String table, NetfilterSystem system)
        {
            if (HasChain(name, table))
            {
                throw new IpTablesNetException("A chain with that name already exists");
            }

            var newChain = new IpTablesChain(table, name, _ipVersion, system);
            AddChain(newChain);
            return newChain;
        }

        public void RemoveChain(IpTablesChain chain)
        {
            _chains.Remove(chain);
        }
    }
}