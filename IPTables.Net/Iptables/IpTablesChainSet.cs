using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using IPTables.Net.Exceptions;
using IPTables.Net.Netfilter;

namespace IPTables.Net.Iptables
{
    public class IpTablesChainSet : IEnumerable<IpTablesChain>
    {
        private int _ipVersion;
        protected HashSet<IpTablesChain> _chains;

        public IpTablesChainSet(int ipVersion)
        {
            _chains = new HashSet<IpTablesChain>();
            _ipVersion = ipVersion;
        }

        public int IpVersion
        {
            get { return _ipVersion; }
        }

        public IEnumerable<IpTablesChain> Chains
        {
            get { return _chains; }
        }


        public void AddDefaultChains(IpTablesSystem system)
        {
            foreach (var tablePair in IPTablesTables.DefaultTables)
            {
                foreach (var chain in tablePair.Value)
                {
                    _chains.Add(new IpTablesChain(tablePair.Key, chain, _ipVersion, system));
                }
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
                if (!other._chains.TryGetValue(c, out c2))
                {
                    return false;
                }
                
                if (!c2.CompareRules(c))
                {
                    return false;
                }
            }

            return true;
        }

        public override bool Equals(object obj)
        {
            if (ReferenceEquals(null, obj)) return false;
            if (ReferenceEquals(this, obj)) return true;
            if (obj.GetType() != this.GetType()) return false;
            return Equals((IpTablesChainSet) obj);
        }

        public override int GetHashCode()
        {
            int hashCode = _ipVersion;
            hashCode = (hashCode * 397) ^ _chains.Count;
            return hashCode;
        }

        public bool HasChain(String chain, String table)
        {
            return GetChainOrDefault(chain, table) != null;
        }

        public void AddChain(IpTablesChain chain)
        {
            if (_chains.Contains(chain))
            {
                throw new IpTablesNetException("Chain Set already contains this chain");
            }

            if (_chains.FirstOrDefault(a => ((IpTablesChain) a).Name == ((IpTablesChain) chain).Name && ((IpTablesChain) a).Table == ((IpTablesChain) chain).Table) != null)
            {
                throw new IpTablesNetException("Chain Set already contains a chain with the same name in this table");
            }

            _chains.Add(chain);
        }

        public IpTablesChain GetChainOrAdd(string chainName, string tableName, IpTablesSystem system)
        {
            IpTablesChain chain = GetChainOrDefault(chainName, tableName);

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
            IpTablesChain chainFound = GetChainOrDefault(((IpTablesChain) chain).Name, ((IpTablesChain) chain).Table);

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
            ((IpTablesChain) chain).AddRule(rule);
        }

        public IpTablesChain GetChainOrDefault(string chain, string table)
        {
            return _chains.FirstOrDefault(a => ((IpTablesChain) a).Name == chain && ((IpTablesChain) a).Table == table);
        }

        public IpTablesChain GetChain(string chain, string table)
        {
            return _chains.First(a => ((IpTablesChain) a).Name == chain && ((IpTablesChain) a).Table == table);
        }

        IEnumerator<IpTablesChain> IEnumerable<IpTablesChain>.GetEnumerator()
        {
            return _chains.Cast<IpTablesChain>().GetEnumerator();
        }

        IEnumerator IEnumerable.GetEnumerator()
        {
            return _chains.GetEnumerator();
        }
    }
}