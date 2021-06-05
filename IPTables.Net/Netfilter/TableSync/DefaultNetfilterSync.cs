using System;
using System.Collections.Generic;
using System.Linq;
using IPTables.Net.Iptables;
using IPTables.Net.Iptables.Adapter.Client;

namespace IPTables.Net.Netfilter.TableSync
{
    public class DefaultNetfilterSync : INetfilterSync
    {
        private Func<IpTablesRule, bool> _shouldDelete = null;

        public Func<IpTablesRule, bool> ShouldDelete
        {
            get => _shouldDelete;
            set
            {
                if (value == null)
                    _shouldDelete = a => true;
                else
                    _shouldDelete = value;
            }
        }

        private Func<IpTablesRule, IpTablesRule, bool> _ruleComparerForUpdate;
        private IEqualityComparer<IpTablesRule> _comparer = null;


        public IEnumerable<string> TableOrder { get; set; } = new List<string> {"raw", "nat", "mangle", "filter"};

        public Func<IpTablesRule, IpTablesRule, bool> RuleComparerForUpdate
        {
            get => _ruleComparerForUpdate;
            set
            {
                if (value == null)
                    _ruleComparerForUpdate = (a, b) => false;
                else
                    _ruleComparerForUpdate = value;
            }
        }

        public DefaultNetfilterSync(Func<IpTablesRule, IpTablesRule, bool> ruleComparerForUpdate = null,
            Func<IpTablesRule, bool> shouldDelete = null, IEqualityComparer<IpTablesRule> comparer = null)
        {
            ShouldDelete = shouldDelete;
            RuleComparerForUpdate = ruleComparerForUpdate;
            _comparer = comparer ?? new IpTablesRule.ValueComparison();
        }

        public void SyncChainRules(IIPTablesAdapterClient client, IEnumerable<IpTablesRule> with, IpTablesChain chain)
        {
            //Copy the rules
            var currentRules = new List<IpTablesRule>(chain.Rules);


            int i = 0, len = with.Count();

            var shouldUpdate = currentRules.Count == len;
            foreach (var cR in currentRules)
            {
                //Delete any extra rules
                if (i == len)
                {
                    if (_shouldDelete(cR)) cR.DeleteRule(client);
                    continue;
                }

                //Get the rule for comparison
                var withRule = with.ElementAt(i);

                var eq = _comparer.Equals(cR, withRule);
                if (eq)
                {
                    //No need to make any changes
                    i++;
                    continue;
                }

                //Debug:
                if (_ruleComparerForUpdate(cR, withRule) || shouldUpdate)
                {
                    //Replace this rule
                    cR.ReplaceRule(client, withRule);
                    i++;
                }
                else
                {
                    // Don't delete if this is non deletable
                    if (_shouldDelete(cR)) cR.DeleteRule(client);
                }
            }

            //Get rules to be added
            foreach (var rR in with.Skip(i))
            {
                var newRule = rR.ShallowClone();
                newRule.Chain = chain;
                newRule.AddRule(client);
            }
        }

        public void SyncChains()
        {
        }
    }
}