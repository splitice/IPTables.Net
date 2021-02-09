using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Sockets;
using System.Threading;
using IPTables.Net.Exceptions;
using IPTables.Net.Iptables.Adapter.Client;
using IPTables.Net.Netfilter.TableSync;

namespace IPTables.Net.Iptables
{
    /// <summary>
    /// A List of rules (and chains!) in an IPTables system
    /// </summary>
    public class IpTablesRuleSet: IEquatable<IpTablesRuleSet>
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

            foreach (string s in rules)
            {
                AddRule(s);
            }
        }
        #endregion

        #region Properties
        public IpTablesChainSet Chains
        {
            get { return _chains; }
        }

        public IEnumerable<IpTablesRule> Rules
        {
            get { return _chains.SelectMany((a) => a.Rules); }
        }

        public int IpVersion
        {
            get { return _ipVersion; }
        }

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
            IpTablesChain ipchain = _chains.GetChainOrAdd(rule.Chain);

            if (position < 0)
            {
                ipchain.Rules.Add(rule);
            }
            else
            {
                ipchain.Rules.Insert(position, rule);
            }
        }


        /// <summary>
        /// Parse and add an IPTables rule to the set
        /// </summary>
        /// <param name="rawRule"></param>
        /// <param name="position"></param>
        /// <returns></returns>
        public IpTablesRule AddRule(String rawRule, int position = -1)
        {
            IpTablesRule rule = IpTablesRule.Parse(rawRule, _system, _chains, _ipVersion);
            AddRule(rule, position);
            return rule;
        }

        /// <summary>
        /// Add a chain to the set
        /// </summary>
        /// <param name="name"></param>
        /// <param name="table"></param>
        public IpTablesChain AddChain(String name, String table)
        {
            return _chains.AddChain(name, table, _system);
        }

        /// <summary>
        /// Sync with an IPTables system
        /// </summary>
        /// <param name="sync"></param>
        /// <param name="canDeleteChain"></param>
        /// <param name="maxRetries"></param>
        public void Sync(INetfilterSync<IpTablesRule> sync,
            Func<IpTablesChain, bool> canDeleteChain = null, int maxRetries = 10)
        {
            using (var client = _system.GetTableAdapter(_ipVersion))
            {
                List<IpTablesChain> chainsToAdd = new List<IpTablesChain>();
                bool needed;
                int retries = maxRetries;

                do
                {
                    try
                    {
                        //Start transaction
                        client.StartTransaction();
                        try
                        {
                            //Load all chains, figure out what to add
                            var tableChains = new Dictionary<string, List<IpTablesChain>>();
                            foreach (IpTablesChain chain in Chains)
                            {
                                if (!tableChains.ContainsKey(chain.Table))
                                {
                                    var chains = _system.GetChains(client, chain.Table, _ipVersion).ToList();
                                    tableChains.Add(chain.Table, chains);
                                }

                                if (
                                    tableChains[chain.Table].FirstOrDefault(
                                        a => a.Name == chain.Name && a.Table == chain.Table) ==
                                    null)
                                {
                                    //Chain doesnt exist, to create
                                    chainsToAdd.Add(chain);
                                }
                            }

                            //Add the new chains / rules
                            foreach (var chain in chainsToAdd)
                            {
                                tableChains[chain.Table].Add(_system.AddChain(client, chain));
                            }

                            chainsToAdd.Clear();

                            //Special case
                            if (client is IPTablesLibAdapterClient)
                            {
                                //Sync chain adds before starting rule adds
                                client.EndTransactionCommit();
                                client.StartTransaction();
                            }

                            //Update chains with differing rules
                            foreach (IpTablesChain chain in Chains)
                            {
                                IpTablesChain realChain =
                                    tableChains[chain.Table].First(a => a.Name == chain.Name && a.Table == chain.Table);
                                if (realChain != null)
                                {
                                    //Update chain
                                    realChain.SyncInternal(client, chain.Rules, sync);
                                }
                            }
                        }
                        catch
                        {
                            try
                            {
                                client.EndTransactionRollback();
                            }
                            catch
                            {
                            }

                            throw;
                        }

                        //End Transaction: COMMIT
                        client.EndTransactionCommit();

                        if (canDeleteChain != null)
                        {
                            //Start transaction
                            //Needs new transaction, bug in libiptc?
                            client.StartTransaction();

                            try
                            {
                                foreach (string table in Chains.Select(a => a.Table).Distinct())
                                {
                                    foreach (IpTablesChain chain in _system.GetChains(table, _ipVersion))
                                    {
                                        if (!_chains.HasChain(chain.Name, chain.Table) && canDeleteChain(chain))
                                        {
                                            chain.Delete(client);
                                        }
                                    }
                                }
                            }
                            catch
                            {
                                try
                                {
                                    client.EndTransactionRollback();
                                }
                                catch
                                {
                                }

                                throw;
                            }

                            //End Transaction: COMMIT
                            client.EndTransactionCommit();
                        }

                        needed = false;
                    }
                    catch (IpTablesNetExceptionErrno ex)
                    {
                        client.EndTransactionRollback();
                        if (ex.Errno == 11 && retries != 0) //Resource Temporarily unavailable
                        {
                            Thread.Sleep(100*(maxRetries - retries));
                            retries--;
                            needed = true;
                        }
                        else
                        {
                            throw;
                        }
                    }
                } while (needed);
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
            if (obj.GetType() != this.GetType()) return false;
            return Equals((IpTablesRuleSet) obj);
        }

        public override int GetHashCode()
        {
            unchecked
            {
                var hashCode = (_chains != null ? _chains.GetHashCode() : 0);
                hashCode = (hashCode * 397) ^ (_system != null ? _system.GetHashCode() : 0);
                hashCode = (hashCode * 397) ^ _ipVersion;
                return hashCode;
            }
        }

        public IpTablesRuleSet DeepClone()
        {
            IpTablesRuleSet rs = new IpTablesRuleSet(IpVersion, System);
            foreach (var chain in _chains)
            {
                rs.AddChain(chain.Name, chain.Table);
            }

            foreach (var rule in Rules)
            {
                rs.AddRule(rule.GetActionCommand());
            }

            return rs;
        }
    }
}