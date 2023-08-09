using System;
using System.Collections.Generic;
using System.Data;
using System.Linq;
using System.Runtime.CompilerServices;
using IPTables.Net.Exceptions;
using IPTables.Net.Iptables.Adapter.Client;
using IPTables.Net.Iptables.TableSync;

[assembly: InternalsVisibleTo("IPTables.Net.Tests")]
[assembly: InternalsVisibleTo("IPTables.Net.TestFramework")]

namespace IPTables.Net.Iptables
{
    public class IpTablesChain : IEquatable<IpTablesChain>
    {
        /// <summary>
        /// Data to define the default and chains
        /// </summary>
        public const string Input = "INPUT";
        public const string Output = "OUTPUT";
        public const string Forward = "FORWARD";
        public const string Prerouting = "PREROUTING";
        public const string Postrouting = "POSTROUTING";

        private readonly string _name;
        private readonly List<IpTablesRule> _rules;
        private readonly IpTablesSystem _system;
        private readonly string _table;
        private readonly int _ipVersion;

        public IpTablesChain(string table, string chainName, int ipVersion, IpTablesSystem system,
            List<IpTablesRule> rules)
        {
            _name = chainName;
            _table = table;
            _system = system;
            _rules = rules;
            _ipVersion = ipVersion;
        }

        public IpTablesChain(string table, string chainName, int ipVersion, IpTablesSystem system)
        {
            _name = chainName;
            _table = table;
            _system = system;
            _rules = new List<IpTablesRule>();
            _ipVersion = ipVersion;
        }

        public bool IsEmpty => !_rules.Any();

        public string Name => _name;

        public string Table => _table;

        public List<IpTablesRule> Rules => _rules;

        public int IpVersion => _ipVersion;

        public void AddRule(IpTablesRule rule)
        {
            Rules.Add(rule);
        }

        public void DeleteRule(int offset)
        {
            Rules.RemoveAt(offset);
        }

        public void DeleteRule(IpTablesRule rule)
        {
            Rules.Remove(rule);
        }

        public void InsertRule(int offset, IpTablesRule rule)
        {
            Rules.Insert(offset, rule);
        }

        public void ReplaceRule(int offset, IpTablesRule rule)
        {
            Rules[offset] = rule;
        }

        public IpTablesSystem System => _system;

        public void Sync(IIPTablesAdapterClient client, IEnumerable<IpTablesRule> with,
            IRuleSync sync)
        {
            client.StartTransaction();

            try
            {
                SyncInternal(client, with, sync);
            }
            catch
            {
                client.EndTransactionRollback();
                throw;
            }

            client.EndTransactionCommit();
        }

        public void Delete(IIPTablesAdapterClient client, bool flush = false)
        {
            _system.DeleteChain(client, _name, _table, _ipVersion, flush);
        }

        public void Delete(bool flush = false)
        {
            _system.DeleteChain(_name, _table, _ipVersion, flush);
        }

        public static bool ValidateChainName(string chainName)
        {
            return chainName.Length <= 30;
        }

        internal void SyncInternal(IIPTablesAdapterClient client, IEnumerable<IpTablesRule> with, IRuleSync sync)
        {
            sync.SyncChainRules(client, with, this);
        }

        public int GetRulePosition(IpTablesRule rule)
        {
            var index = Rules.IndexOf(rule);
            if (index == -1) return -1;
            return index + 1;
        }

        public bool Equals(IpTablesChain other)
        {
            if (ReferenceEquals(null, other)) return false;
            if (ReferenceEquals(this, other)) return true;
            return string.Equals(_name, other._name) && string.Equals(_table, other._table) &&
                   Equals(_system, other._system) && _ipVersion == other._ipVersion;
        }

        public override bool Equals(object obj)
        {
            if (ReferenceEquals(null, obj)) return false;
            if (ReferenceEquals(this, obj)) return true;
            if (obj.GetType() != GetType()) return false;
            return Equals((IpTablesChain) obj);
        }

        public override int GetHashCode()
        {
            unchecked
            {
                var hashCode = _name != null ? _name.GetHashCode() : 0;
                hashCode = (hashCode * 397) ^ (_table != null ? _table.GetHashCode() : 0);
                hashCode = (hashCode * 397) ^ (_system != null ? _system.GetHashCode() : 0);
                hashCode = (hashCode * 397) ^ _ipVersion.GetHashCode();
                return hashCode;
            }
        }

        public bool CompareRules(IpTablesChain ipTablesChain, IEqualityComparer<IpTablesRule> eqc = null)
        {
            eqc = eqc ?? new IpTablesRule.ValueComparison();
            return Enumerable.SequenceEqual(_rules, ipTablesChain._rules, eqc);
        }
    }
}