using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using IPTables.Net.Exceptions;

namespace IPTables.Net.Iptables.RuleGenerator
{
    internal class RuleOutputter : IRuleGenerator
    {
        private List<IpTablesRule> _rules = new List<IpTablesRule>();
        private string _chain;
        private string _table;

        public RuleOutputter(string chain = null, string table = null)
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
                    var chain = ruleSet.Chains.GetChainOrDefault(_chain, _table);
                    if (chain == null) throw new IpTablesNetException("Unable to find chain");
                    rule.Chain = chain;
                }

                ruleSet.AddRule(rule);
            }
        }
    }
}