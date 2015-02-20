using System;
using System.Collections.Generic;
using System.Linq;
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
        private readonly IpTablesChainSet _chains = new IpTablesChainSet();

        /// <summary>
        /// The IPTables system
        /// </summary>
        private readonly IpTablesSystem _system;
        #endregion

        #region Constructors
        public IpTablesRuleSet(IpTablesSystem system)
        {
            _system = system;
        }

        public IpTablesRuleSet(IEnumerable<string> rules, IpTablesSystem system)
        {
            _system = system;
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
            IpTablesRule rule = IpTablesRule.Parse(rawRule, _system, _chains);
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
        public void Sync(INetfilterSync<IpTablesRule> sync,
            Func<IpTablesChain, bool> canDeleteChain = null)
        {
            //Start transaction
            _system.TableAdapter.StartTransaction();
            
            var tableChains = new Dictionary<string, List<IpTablesChain>>();
            foreach (IpTablesChain chain in Chains)
            {
                if (!tableChains.ContainsKey(chain.Table))
                {
                    var chains = _system.GetChains(chain.Table).ToList();
                    tableChains.Add(chain.Table, chains);
                }
                if (tableChains[chain.Table].FirstOrDefault(a => a.Name == chain.Name && a.Table == chain.Table) == null)
                {
                    //Chain doesnt exist create
                    tableChains[chain.Table].Add(_system.AddChain(chain));
                }
            }

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

            if (canDeleteChain != null)
            {
                foreach (string table in Chains.Select(a => a.Table).Distinct())
                {
                    foreach (IpTablesChain chain in _system.GetChains(table))
                    {
                        if (!_chains.HasChain(chain.Name, chain.Table) && canDeleteChain(chain))
                        {
                            chain.Delete();
                        }
                    }
                }
            }

            //End Transaction: COMMIT
            _system.TableAdapter.EndTransactionCommit();
        }

        #endregion
    }
}