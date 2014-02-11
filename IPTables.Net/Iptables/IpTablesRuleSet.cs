using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using IPTables.Net.Iptables.Modules;
using IPTables.Net.Iptables.Modules.Core;

namespace IPTables.Net.Iptables
{
    public class IpTablesRuleSet
    {
        private IpTablesChainSet _chains = new IpTablesChainSet();

        public IEnumerable<IpTablesChain> Chains
        {
            get
            {
                return _chains.Chains;
            }
        }

        public IpTablesChainSet ChainSet
        {
            get
            {
                return _chains;
            }
        }

        private IpTablesSystem _system;
        public IpTablesRuleSet(IpTablesSystem system)
        {
            _system = system;
        }

        public IpTablesRuleSet(List<string> rules, IpTablesSystem system)
        {
            _system = system;
            foreach (var s in rules)
            {
                AddRule(s);
            }
        }


        public void AddRule(IpTablesRule rule)
        {
            var ipchain = _chains.GetChainOrAdd(rule.Chain);

            ipchain.Rules.Add(rule);
        }

        public IpTablesRule AddRule(String rawRule)
        {
            var rule = IpTablesRule.Parse(rawRule, _system, _chains);

            AddRule(rule);

            return rule;
        }

        

        public void AddChain(String name, String table)
        {
            if (_chains.HasChain(name, table))
            {
                throw new Exception("A chain with that name already exists");
            }

            _chains.AddChain(new IpTablesChain(table, name, _system));
        }

        public void SyncChains(Func<IpTablesRule, IpTablesRule, bool> comparer = null, Func<IpTablesChain, bool> canDeleteChain = null)
        {
            var tableChains = new Dictionary<string, List<IpTablesChain>>();
            foreach (var chain in Chains)
            {
                if(!tableChains.ContainsKey(chain.Table))
                {
                    tableChains.Add(chain.Table, _system.GetChains(chain.Table).ToList());
                }
                if (tableChains[chain.Table].FirstOrDefault((a)=>a.Name == chain.Name) == null)
                {
                    //Chain doesnt exist create
                    _system.AddChain(chain);
                    tableChains[chain.Table].Add(new IpTablesChain(chain.Table, chain.Name, _system));
                }
            }

            foreach (var chain in Chains)
            {
                var realChain = tableChains[chain.Table].First((a) => a.Name == chain.Name && a.Table == chain.Table);
                if (realChain != null)
                {
                    //Update chain
                    realChain.Sync(chain.Rules, comparer);
                }
            }

            if (canDeleteChain != null)
            {
                foreach (var table in Chains.Select((a) => a.Table).Distinct())
                {
                    foreach (var chain in _system.GetChains(table))
                    {
                        if (!_chains.HasChain(chain.Name, chain.Table) && canDeleteChain(chain))
                        {
                            chain.Delete();
                        }
                    }
                }
            }
        }
    }
}
