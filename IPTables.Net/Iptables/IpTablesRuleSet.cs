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
        private List<IpTablesChain> _chains = new List<IpTablesChain>();

        public IEnumerable<IpTablesChain> Chains
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


        public void AddRule(String chain, IpTablesRule rule)
        {
            var coreModule = rule.GetModule<CoreModule>("core");
            var table = coreModule.Table;

            if (_chains.FirstOrDefault((a) => a.Name == chain && a.Table == table) == null)
            {
                _chains.Add(new IpTablesChain(table, chain, _system));
            }

            var ipchain = _chains.First((a) => a.Name == chain && a.Table == table);

            ipchain.Rules.Add(rule);
        }

        public IpTablesRule AddRule(String rawRule)
        {
            String chain;
            var rule = IpTablesRule.Parse(rawRule, _system.System, out chain);

            AddRule(chain, rule);

            return rule;
        }

        public bool HasChain(String name, String table)
        {
            return _chains.FirstOrDefault((a) => a.Name == name && a.Table == table) != null;
        }

        public void AddChain(String name, String table)
        {
            if (HasChain(name, table))
            {
                throw new Exception("A chain with that name already exists");
            }

            _chains.Add(new IpTablesChain(table, name, _system));
        }

        public void SyncChains(Func<IpTablesRule, IpTablesRule, bool> comparer = null, Func<IpTablesChain, bool> canDeleteChain = null)
        {
            foreach (var chain in Chains)
            {
                var realChain = _system.GetChain(chain.Table, chain.Name);
                if (realChain == null)
                {
                    //Chain doesnt exist create
                    _system.AddChain(chain);
                }
                else
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
                        if (!HasChain(chain.Name, chain.Table) && canDeleteChain(chain))
                        {
                            chain.Delete();
                        }
                    }
                }
            }
        }
    }
}
