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

        public IpTablesChain(String table, String chainName, NetfilterSystem system, List<IpTablesRule> rules)
        {
            _name = chainName;
            _table = table;
            _system = system;
            _rules = rules;
        }

        public IpTablesChain(String table, String chainName, NetfilterSystem system)
        {
            _name = chainName;
            _table = table;
            _system = system;
            _rules = new List<IpTablesRule>();
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

        internal NetfilterSystem System
        {
            get { return _system; }
        }

        public void Sync(IEnumerable<IpTablesRule> with,
            INetfilterSync<IpTablesRule> sync)
        {
            _system.TableAdapter.StartTransaction();

            SyncInternal(with, sync);

            _system.TableAdapter.EndTransactionCommit();
        }

        public void Delete(bool flush = false)
        {
            _system.DeleteChain(_name, _table, flush);
        }

        internal void SyncInternal(IEnumerable<IpTablesRule> with,
            INetfilterSync<IpTablesRule> sync)
        {
            sync.SyncChainRules(with, Rules);
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
            //Console.WriteLine(String.Format("Equality: {0},{1},{2}", string.Equals(_name, other._name), string.Equals(_table, other._table), Equals(_system, other._system)));
            if (ReferenceEquals(null, other)) return false;
            if (ReferenceEquals(this, other)) return true;
            return string.Equals(_name, other._name) && string.Equals(_table, other._table) && Equals(_system, other._system);
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
                hashCode = (hashCode*397) ^ (_system != null ? _system.GetHashCode() : 0);
                return hashCode;
            }
        }
    }
}