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

        public void AddChain(String name, String table)
        {
            if (_chains.FirstOrDefault((a) => a.Name == name && a.Table == table) != null)
            {
                throw new Exception("A chain with that name already exists");
            }

            _chains.Add(new IpTablesChain(table, name, _system));
        }

        public void SyncChains(Func<IpTablesRule, IpTablesRule, bool> comparer = null, bool deleteUndefinedChains = false)
        {
            foreach (var chain in Chains)
            {
                var realChain = _system.GetChain(chain.Table, chain.Name);
                realChain.Sync(chain.Rules, comparer);
            }

            if (deleteUndefinedChains)
            {
                throw new NotImplementedException("Deletion of non defined chains not implemented yet");
            }
        }
    }
}
