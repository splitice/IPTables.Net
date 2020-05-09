using System;
using System.Collections.Generic;
using System.Linq;

namespace IPTables.Net.Netfilter.TableSync
{
    public class DefaultNetfilterSync<T> : INetfilterSync<T> where T : INetfilterRule
    {
        private Func<T, bool> _shouldDelete = null;

        public Func<T, bool> ShouldDelete
        {
            get { return _shouldDelete; }
            set
            {
                if (value == null)
                {
                    _shouldDelete = a => true;
                }
                else
                {
                    _shouldDelete = value;
                }
            }
        }

        private Func<T, T, bool> _ruleComparerForUpdate;
        private bool _debug;

        public Func<T, T, bool> RuleComparerForUpdate
        {
            get { return _ruleComparerForUpdate; }
            set
            {
                if (value == null)
                {
                    _ruleComparerForUpdate = (a, b) => false;
                }
                else
                {
                    _ruleComparerForUpdate = value;
                }
            }
        }

        public DefaultNetfilterSync(Func<T, T, bool> ruleComparerForUpdate, Func<T, bool> shouldDelete = null, bool debug = false)
        {
            ShouldDelete = shouldDelete;
            RuleComparerForUpdate = ruleComparerForUpdate;
            _debug = debug;
        } 

        public void SyncChainRules(INetfilterAdapterClient client, IEnumerable<T> with, IEnumerable<T> currentRulesEnum)
        {
            //Copy the rules
            var currentRules = new List<T>(currentRulesEnum);

            
            int i = 0, len = with.Count();

            bool shouldUpdate = currentRules.Count == len;
            foreach (T cR in currentRules)
            {
                //Delete any extra rules
                if (i == len)
                {
                    if (_shouldDelete(cR))
                    {
                        cR.DeleteRule(client);
                    }
                    continue;
                }

                //Get the rule for comparison
                T withRule = with.ElementAt(i);

                bool eq;
                if (_debug)
                {
                    eq = cR.DebugEquals(withRule, true);
                }
                else
                {
                    eq = cR.Equals(withRule);
                }

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
                    if (_shouldDelete(cR))
                    {
                        cR.DeleteRule(client);
                    }
                }
            }

            //Get rules to be added
            foreach (T rR in with.Skip(i))
            {
                rR.AddRule(client);
            }
        }

        public void SyncChains()
        {
            
        }

        public void SyncChainRules(INetfilterAdapterClient client, IEnumerable<INetfilterRule> with, IEnumerable<INetfilterRule> currentRules)
        {
            var withCast = with.Cast<T>();
            var currentRulesCast = currentRules.Cast<T>();

            SyncChainRules(client, withCast, currentRulesCast);
        }
    }
}
