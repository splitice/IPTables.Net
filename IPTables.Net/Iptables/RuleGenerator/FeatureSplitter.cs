using System;
using System.Collections.Generic;
using IPTables.Net.Iptables.Modules.Comment;
using IPTables.Net.Iptables.Modules.Core;

namespace IPTables.Net.Iptables.RuleGenerator
{
    class FeatureSplitter<TGenerator, TKey>: IRuleGenerator where TGenerator : IRuleGenerator
    {
        private Dictionary<TKey, IRuleGenerator> _protocols = new Dictionary<TKey, IRuleGenerator>();
        private string _chain;
        private string _table;
        private Func<IpTablesRule, TKey> _extractor;
        private Func<String, String, TGenerator> _nestedGenerator;
        private Action<IpTablesRule, TKey> _setter;
        private string _commentPrefix;

        public FeatureSplitter(String chain, String table, Func<IpTablesRule, TKey> extractor, Action<IpTablesRule, TKey> setter, Func<String, String, TGenerator> nestedGenerator, String commentPrefix)
        {
            _chain = chain;
            _table = table;
            _extractor = extractor;
            _setter = setter;
            _nestedGenerator = nestedGenerator;
            _commentPrefix = commentPrefix;
        }

        public void AddRule(IpTablesRule rule)
        {
            TKey key = _extractor(rule);
            if (!_protocols.ContainsKey(key))
            {
                _protocols.Add(key, _nestedGenerator(_chain + "|" + key, _table));
            }

            var gen = _protocols[key];
            
            gen.AddRule(rule);
        }

        public void Output(IpTablesSystem system, IpTablesRuleSet ruleSet)
        {
            foreach (var p in _protocols)
            {
                String chainName = _chain + "|" + p.Key;
                if(ruleSet.ChainSet.HasChain(chainName, _table))
                {
                    throw new Exception(String.Format("Duplicate feature split: {0}", chainName));
                }

                //Jump to chain
                var chain = ruleSet.ChainSet.GetChainOrAdd(_chain, _table, system);
                IpTablesRule jumpRule = new IpTablesRule(system, chain);
                jumpRule.GetModuleOrLoad<CoreModule>("core").Jump = chainName;
                jumpRule.GetModuleOrLoad<CommentModule>("comment").CommentText = _commentPrefix+"|FS|"+chainName;
                _setter(jumpRule, p.Key);
                ruleSet.AddRule(jumpRule);

                //Nested output

                ruleSet.AddChain(chainName, _table);
                p.Value.Output(system, ruleSet);
            }
        }
    }

    class FeatureSplitter<TGenerator> : FeatureSplitter<TGenerator, String> where TGenerator : IRuleGenerator
    {
        public FeatureSplitter(string chain, string table, Func<IpTablesRule, string> extractor, Action<IpTablesRule, string> setter, Func<string, string, TGenerator> nestedGenerator, string commentPrefix) : base(chain, table, extractor, setter, nestedGenerator, commentPrefix)
        {
        }
    }
}
