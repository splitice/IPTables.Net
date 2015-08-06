using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using IPTables.Net.Exceptions;
using IPTables.Net.Iptables.Adapter.Client;
using IPTables.Net.Netfilter.TableSync;

namespace IPTables.Net.Iptables
{
    /// <summary>
    /// A List of rules (and chains!) in an IPTables system
    /// </summary>
    public class IpTablesRuleSet
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
        #endregion

        #region Methods

        /// <summary>
        /// Add an IPTables rule to the set
        /// </summary>
        /// <param name="rule"></param>
        public void AddRule(IpTablesRule rule)
        {
            IpTablesChain ipchain = _chains.GetChainOrAdd(rule.Chain);

            ipchain.Rules.Add(rule);
        }


        /// <summary>
        /// Parse and add an IPTables rule to the set
        /// </summary>
        /// <param name="rawRule"></param>
        /// <returns></returns>
        public IpTablesRule AddRule(String rawRule)
        {
            IpTablesRule rule = IpTablesRule.Parse(rawRule, _system, _chains, _ipVersion);
            AddRule(rule);
            return rule;
        }

        /// <summary>
        /// Add a chain to the set
        /// </summary>
        /// <param name="name"></param>
        /// <param name="table"></param>
        public void AddChain(String name, String table)
        {
            _chains.AddChain(name, table, _system);
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
            var tableAdapter = _system.GetTableAdapter(_ipVersion);
            List<IpTablesChain> chainsToAdd = new List<IpTablesChain>();
            bool needed;
            int retries = maxRetries;

            do
            {
                try
                {
                    //Start transaction
                    tableAdapter.StartTransaction();

                    //Load all chains, figure out what to add
                    var tableChains = new Dictionary<string, List<IpTablesChain>>();
                    foreach (IpTablesChain chain in Chains)
                    {
                        if (!tableChains.ContainsKey(chain.Table))
                        {
                            var chains = _system.GetChains(chain.Table, _ipVersion).ToList();
                            tableChains.Add(chain.Table, chains);
                        }
                        if (
                            tableChains[chain.Table].FirstOrDefault(a => a.Name == chain.Name && a.Table == chain.Table) ==
                            null)
                        {
                            //Chain doesnt exist, to create
                            chainsToAdd.Add(chain);
                        }
                    }

                    //Add the new chains / rules
                    foreach (var chain in chainsToAdd)
                    {
                        tableChains[chain.Table].Add(_system.AddChain(chain));
                    }
                    chainsToAdd.Clear();

                    //Special case
                    if (tableAdapter is IPTablesLibAdapterClient)
                    {
                        //Sync chain adds before starting rule adds
                        tableAdapter.EndTransactionCommit();
                        tableAdapter.StartTransaction();
                    }

                    //Update chains with differing rules
                    foreach (IpTablesChain chain in Chains)
                    {
                        IpTablesChain realChain =
                            tableChains[chain.Table].First(a => a.Name == chain.Name && a.Table == chain.Table);
                        if (realChain != null)
                        {
                            //Update chain
                            realChain.SyncInternal(chain.Rules, sync);
                        }
                    }

                    //End Transaction: COMMIT
                    tableAdapter.EndTransactionCommit();

                    if (canDeleteChain != null)
                    {
                        //Start transaction
                        //Needs new transaction, bug in libiptc?
                        tableAdapter.StartTransaction();

                        foreach (string table in Chains.Select(a => a.Table).Distinct())
                        {
                            foreach (IpTablesChain chain in _system.GetChains(table, _ipVersion))
                            {
                                if (!_chains.HasChain(chain.Name, chain.Table) && canDeleteChain(chain))
                                {
                                    chain.Delete();
                                }
                            }
                        }

                        //End Transaction: COMMIT
                        tableAdapter.EndTransactionCommit();
                    }

                    needed = false;
                }
                catch (IpTablesNetExceptionErrno ex)
                {
                    tableAdapter.EndTransactionRollback();
                    if (ex.Errno == 11 && retries != 0)//Resource Temporarily unavailable
                    {
                        Thread.Sleep(100 * (maxRetries - retries));
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

        #endregion
    }
}