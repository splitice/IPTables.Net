using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace IPTables.Net.Iptables.RuleGenerator
{
    class RuleOutputter: IRuleGenerator
    {
        private List<IpTablesRule> _rules = new List<IpTablesRule>();
        private string _chain;
        private string _table;

        public RuleOutputter(String chain = null, String table = null)
        {
            _chain = chain;
            _table = table;
        }
 
        public void AddRule(IpTablesRule rule)
        {
            _rules.Add(rule);
        }

        public void Output(IpTablesSystem system, IpTablesRuleSet ruleSet)
        {
            foreach (var rule in _rules)
            {
                if (_chain != null)
                {
                    var chain = ruleSet.ChainSet.GetChainOrDefault(_chain, _table);
                    if (chain == null)
                    {
                        throw new Exception("Unable to find chain");
                    }
                    rule.Chain = chain;
                }
                ruleSet.AddRule(rule);
            }
        }
    }
}
