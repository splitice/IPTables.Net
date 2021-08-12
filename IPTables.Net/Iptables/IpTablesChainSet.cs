using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using IPTables.Net.Exceptions;

namespace IPTables.Net.Iptables
{
    public class IpTablesChainSet : IEnumerable<IpTablesChain>
    {
        private int _ipVersion;
        protected HashSet<IpTablesChain> _chains;

        public IpTablesChainSet(int ipVersion)
        {
            _chains = new HashSet<IpTablesChain>(new IpTablesChainDetailEquality());
            _ipVersion = ipVersion;
        }

        public int IpVersion => _ipVersion;

        public IEnumerable<IpTablesChain> Chains => _chains;

        public void AddDefaultChains(String table, IpTablesSystem system)
        {
            var list = IPTablesTables.DefaultTables[table];
            foreach (var chain in list)
                _chains.Add(new IpTablesChain(table, chain, _ipVersion, system));
        }

        public void AddDefaultChains(IpTablesSystem system)
        {
            foreach (var tablePair in IPTablesTables.DefaultTables)
            {
                AddDefaultChains(tablePair.Key, system);
            }
        }

        protected IpTablesChain CreateChain(string tableName, string chainName, IpTablesSystem system)
        {
            return new IpTablesChain(tableName, chainName, _ipVersion, system);
        }

        public void RemoveChain(IpTablesChain chain)
        {
            _chains.Remove(chain);
        }

        protected bool Equals(IpTablesChainSet other)
        {
            if (_ipVersion != other._ipVersion || _chains.Count != other._chains.Count) return false;

            foreach (var c in _chains)
            {
                IpTablesChain c2;
                if (!other._chains.TryGetValue(c, out c2)) return false;

                if (!c2.CompareRules(c)) return false;
            }

            return true;
        }

        public override bool Equals(object obj)
        {
            if (ReferenceEquals(null, obj)) return false;
            if (ReferenceEquals(this, obj)) return true;
            if (obj.GetType() != GetType()) return false;
            return Equals((IpTablesChainSet) obj);
        }

        public override int GetHashCode()
        {
            var hashCode = _ipVersion;
            hashCode = (hashCode * 397) ^ _chains.Count;
            return hashCode;
        }

        public bool HasChain(string chain, string table)
        {
            return GetChainOrDefault(chain, table) != null;
        }

        public bool HasChain(IpTablesChain chain)
        {
            return _chains.Contains(chain);
        }

        public void AddChain(IpTablesChain chain)
        {
            if (HasChain(chain)) throw new IpTablesNetException(String.Format("ChainSet already contains {0} chain", chain.Name));

            _chains.Add(chain);
        }

        public IpTablesChain GetChainOrAdd(string chainName, string tableName, IpTablesSystem system)
        {
            var chain = GetChainOrDefault(chainName, tableName);

            if (chain != null)
                return chain;

            return AddChain(chainName, tableName, system);
        }


        public IpTablesChain AddChain(string chainName, string tableName, IpTablesSystem system)
        {
            var chain = CreateChain(tableName, chainName, system);
            AddChain(chain);
            return chain;
        }

        public IpTablesChain GetChainOrAdd(IpTablesChain chain)
        {
            var chainFound = GetChainOrDefault(((IpTablesChain) chain).Name, ((IpTablesChain) chain).Table);

            if (chainFound == null)
                AddChain(chain);
            else
                return chainFound;


            return chain;
        }

        public void AddRule(IpTablesRule rule)
        {
            var chain = GetChainOrAdd(rule.Chain);
            chain.AddRule(rule);
        }

        public IpTablesChain GetChainOrDefault(string chain, string table)
        {
            IpTablesChain c = new IpTablesChain(table, chain, _ipVersion, null);
            IpTablesChain ret;
            _chains.TryGetValue(c, out ret);
            return ret;
        }

        public IpTablesChain GetChain(string chain, string table)
        {
            var ret = GetChainOrDefault(chain, table);
            if (ret == null)
            {
                throw new InvalidOperationException(String.Format("Chain {0} not found", chain));
            }

            return ret;
        }

        IEnumerator<IpTablesChain> IEnumerable<IpTablesChain>.GetEnumerator()
        {
            return _chains.GetEnumerator();
        }

        IEnumerator IEnumerable.GetEnumerator()
        {
            return _chains.GetEnumerator();
        }
    }
}