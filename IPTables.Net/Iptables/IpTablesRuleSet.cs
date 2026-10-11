using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Sockets;
using System.Threading;
using IPTables.Net.Exceptions;
using IPTables.Net.Iptables.Adapter.Client;
using IPTables.Net.Iptables.TableSync;

namespace IPTables.Net.Iptables
{
    /// <summary>
    /// A List of rules (and chains!) in an IPTables system
    /// </summary>
    public class IpTablesRuleSet : IEquatable<IpTablesRuleSet>
    {
        #region Fields

        /// <summary>
        /// The chains in this set
        /// </summary>
        private readonly IpTablesChainSet _chains;

        /// <summary>
        /// The IPTables system
        /// </summary>
        private readonly IpTablesSystem _system;

        private int _ipVersion;

        #endregion

        #region Constructors

        public IpTablesRuleSet(int ipVersion, IpTablesSystem system)
        {
            _system = system;
            _ipVersion = ipVersion;
            _chains = new IpTablesChainSet(ipVersion);
        }

        public IpTablesRuleSet(int ipVersion, IEnumerable<string> rules, IpTablesSystem system)
        {
            _system = system;
            _ipVersion = ipVersion;
            _chains = new IpTablesChainSet(ipVersion);

            foreach (var s in rules) AddRule(s);
        }

        #endregion

        #region Properties

        public IpTablesChainSet Chains => _chains;

        public IEnumerable<IpTablesRule> Rules
        {
            get { return _chains.SelectMany((a) => a.Rules); }
        }

        public int IpVersion => _ipVersion;

        public AddressFamily AddressFamily
        {
            get
            {
                if (_ipVersion == 4) return AddressFamily.InterNetwork;
                if (_ipVersion == 6) return AddressFamily.InterNetworkV6;
                return AddressFamily.Unknown;
            }
        }

        public IpTablesSystem System => _system;

        #endregion

        #region Methods

        public void ApplyCommand(IpTablesCommand command)
        {
            var chain = Chains.GetChain(command.ChainName, command.Table);

            switch (command.Type)
            {
                case IpTablesCommandType.Add:
                    chain.AddRule(command.Rule);
                    return;
                case IpTablesCommandType.Delete:
                    chain.DeleteRule(command.Offset);
                    return;
                case IpTablesCommandType.Replace:
                    chain.ReplaceRule(command.Offset, command.Rule);
                    return;
                case IpTablesCommandType.Insert:
                    chain.InsertRule(command.Offset, command.Rule);
                    return;
            }

            throw new IpTablesNetException("Unknown command");
        }

        /// <summary>
        /// Add an IPTables rule to the set
        /// </summary>
        /// <param name="rule"></param>
        /// <param name="position"></param>
        public void AddRule(IpTablesRule rule, int position = -1)
        {
            var ipchain = _chains.GetChainOrAdd(rule.Chain);

            if (position < 0)
                ipchain.Rules.Add(rule);
            else
                ipchain.Rules.Insert(position, rule);
        }


        /// <summary>
        /// Parse and add an IPTables rule to the set
        /// </summary>
        /// <param name="rawRule"></param>
        /// <param name="position"></param>
        /// <returns></returns>
        public IpTablesRule AddRule(string rawRule, int position = -1)
        {
            var rule = IpTablesRule.Parse(rawRule, _system, _chains, _ipVersion);
            AddRule(rule, position);
            return rule;
        }

        /// <summary>
        /// Add a chain to the set
        /// </summary>
        /// <param name="name"></param>
        /// <param name="table"></param>
        public IpTablesChain AddChain(string name, string table)
        {
            return _chains.AddChain(name, table, _system);
        }

        /// <summary>
        /// Sync with an IPTables system
        /// </summary>
        /// <param name="sync"></param>
        /// <param name="canDeleteChain"></param>
        /// <param name="maxRetries"></param>
        public void Sync(IRuleSync sync,
            Func<IpTablesChain, bool> canDeleteChain = null, int maxRetries = 10)
        {
            if (maxRetries < 0) throw new ArgumentOutOfRangeException(nameof(maxRetries));
            using var client = _system.GetTableAdapter(_ipVersion);
            for (int attempt = 0; ; attempt++)
            {
                try
                {
                    client.StartTransaction();
                    var tables = Chains.Select(c => c.Table).Distinct().ToList();
                    var current = tables.ToDictionary(t => t, t => _system.GetChains(client, t).ToList());
                    foreach (var chain in Chains)
                        if (!current[chain.Table].Any(c => c.Name == chain.Name))
                            current[chain.Table].Add(_system.AddChain(client, chain));
                    if (client is IPTablesLibAdapterClient)
                    {
                        client.EndTransactionCommit();
                        client.StartTransaction();
                    }
                    foreach (var chain in Chains)
                        current[chain.Table].First(c => c.Name == chain.Name).SyncInternal(client, chain.Rules, sync);
                    client.EndTransactionCommit();
                    if (canDeleteChain != null)
                    {
                        client.StartTransaction();
                        foreach (var table in tables)
                        foreach (var chain in _system.GetChains(client, table))
                            if (!_chains.HasChain(chain.Name, table) && canDeleteChain(chain)) chain.Delete(client);
                        if (client is IPTablesLibAdapterClient native) native.EndTransactionCommit(sync.TableOrder);
                        else client.EndTransactionCommit();
                    }
                    return;
                }
                catch (Exception ex)
                {
                    try { client.EndTransactionRollback(); } catch { /* Preserve the original failure. */ }
                    if (ex is not IpTablesNetExceptionErrno error || error.Errno != 11 || attempt >= maxRetries) throw;
                    Thread.Sleep(100 * attempt);
                }
            }
        }

        #endregion

        public bool Equals(IpTablesRuleSet other)
        {
            return _chains.Equals(other._chains) && Equals(_system, other._system) && _ipVersion == other._ipVersion;
        }

        public override bool Equals(object obj)
        {
            if (ReferenceEquals(null, obj)) return false;
            if (ReferenceEquals(this, obj)) return true;
            if (obj.GetType() != GetType()) return false;
            return Equals((IpTablesRuleSet) obj);
        }

        public override int GetHashCode()
        {
            unchecked
            {
                var hashCode = _chains != null ? _chains.GetHashCode() : 0;
                hashCode = (hashCode * 397) ^ (_system != null ? _system.GetHashCode() : 0);
                hashCode = (hashCode * 397) ^ _ipVersion;
                return hashCode;
            }
        }

        public IpTablesRuleSet DeepClone()
        {
            var rs = new IpTablesRuleSet(IpVersion, System);
            foreach (var chain in _chains) rs.AddChain(chain.Name, chain.Table);

            foreach (var rule in Rules) rs.AddRule(rule.GetActionCommand());

            return rs;
        }
    }
}