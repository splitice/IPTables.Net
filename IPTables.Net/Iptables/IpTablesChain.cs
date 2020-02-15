using System;
using System.Collections.Generic;
using System.Linq;
using IPTables.Net.Exceptions;
using IPTables.Net.Netfilter;
using IPTables.Net.Netfilter.TableSync;

namespace IPTables.Net.Iptables
{
    public class IpTablesChain : INetfilterChain, IEquatable<IpTablesChain>
    {
        private readonly String _name;
        private readonly List<IpTablesRule> _rules;
        private readonly NetfilterSystem _system;
        private readonly String _table;
        private readonly int _ipVersion;

        public IpTablesChain(String table, String chainName, int ipVersion, NetfilterSystem system, List<IpTablesRule> rules)
        {
            _name = chainName;
            _table = table;
            _system = system;
            _rules = rules;
            _ipVersion = ipVersion;
        }

        public IpTablesChain(String table, String chainName, int ipVersion, NetfilterSystem system)
        {
            _name = chainName;
            _table = table;
            _system = system;
            _rules = new List<IpTablesRule>();
            _ipVersion = ipVersion;
        }

        public bool IsEmpty
        {
            get { return !_rules.Any(); }
        }

        public String Name
        {
            get { return _name; }
        }

        public String Table
        {
            get { return _table; }
        }

        public List<IpTablesRule> Rules
        {
            get { return _rules; }
        }

        public int IpVersion
        {
            get { return _ipVersion; }
        }

        public void AddRule(INetfilterRule rule)
        {
            var ruleCast = rule as IpTablesRule;
            if(ruleCast == null)
                throw new IpTablesNetException("Invalid rule type for this chain");

            Rules.Add(ruleCast);
        }

        IEnumerable<INetfilterRule> INetfilterChain.Rules
        {
            get { return _rules.Cast<INetfilterRule>(); }
        } 

        public NetfilterSystem System
        {
            get { return _system; }
        }

        public void Sync(INetfilterAdapterClient client, IEnumerable<IpTablesRule> with,
            INetfilterSync<IpTablesRule> sync)
        {
            client.StartTransaction();

            SyncInternal(client, with, sync);

            client.EndTransactionCommit();
        }

        public void Delete(INetfilterAdapterClient client, bool flush = false)
        {
            _system.DeleteChain(client, _name, _table, _ipVersion, flush);
        }

        public void Delete(bool flush = false)
        {
            _system.DeleteChain(_name, _table, _ipVersion, flush);
        }

        public static bool ValidateChainName(String chainName)
        {
            if (chainName.Length > 30)
            {
                return false;
            }
            return true;
        }

        internal void SyncInternal(INetfilterAdapterClient client, IEnumerable<IpTablesRule> with, INetfilterSync<IpTablesRule> sync)
        {
            sync.SyncChainRules(client, with, Rules);
        }

        public int GetRulePosition(IpTablesRule rule)
        {
            var index = Rules.IndexOf(rule);
            if (index == -1)
            {
                return -1;
            }
            return index + 1;
        }

        public bool Equals(IpTablesChain other)
        {
            if (ReferenceEquals(null, other)) return false;
            if (ReferenceEquals(this, other)) return true;
            return string.Equals(_name, other._name) && string.Equals(_table, other._table) && Equals(_system, other._system) && _ipVersion == other._ipVersion;
        }

        public override bool Equals(object obj)
        {
            if (ReferenceEquals(null, obj)) return false;
            if (ReferenceEquals(this, obj)) return true;
            if (obj.GetType() != this.GetType()) return false;
            return Equals((IpTablesChain) obj);
        }

        public override int GetHashCode()
        {
            unchecked
            {
                int hashCode = (_name != null ? _name.GetHashCode() : 0);
                hashCode = (hashCode*397) ^ (_table != null ? _table.GetHashCode() : 0);
                hashCode = (hashCode * 397) ^ (_system != null ? _system.GetHashCode() : 0);
                hashCode = (hashCode * 397) ^ _ipVersion.GetHashCode();
                return hashCode;
            }
        }
    }
}