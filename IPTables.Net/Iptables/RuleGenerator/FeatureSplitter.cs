using System;
using System.Collections.Generic;
using IPTables.Net.Exceptions;
using IPTables.Net.Iptables.Helpers;
using IPTables.Net.Iptables.Modules.Comment;
using IPTables.Net.Iptables.Modules.Core;

namespace IPTables.Net.Iptables.RuleGenerator
{
    /// <summary>
    /// Split rules by a specific condition and build a jump based on that condition.
    /// 
    /// e.g
    /// 
    /// Input:
    /// iptables -A INPUT -p tcp -m tcp --dport 80 -j CHAIN1
    /// iptables -A INPUT -p tcp -m tcp --dport 81 --syn -j CHAIN2
    /// iptables -A INPUT -p udp -m udp --dport 99 -j CHAIN3
    /// 
    /// Output:
    /// iptables -A INPUT -p tcp -g INPUT_tcp
    /// iptables -A INPUT -p udp -g INPUT_udp
    /// iptables -A INPUT_tcp -p tcp -m tcp --dport 80 -j CHAIN1
    /// iptables -A INPUT_tcp -p tcp -m tcp --dport 81 --syn -j CHAIN2
    /// iptables -A INPUT_tcp -p udp -m udp --dport 99 -j CHAIN3
    /// 
    /// 
    /// This can be used to optimize large lists of rules.
    /// </summary>
    /// <typeparam name="TGenerator"></typeparam>
    /// <typeparam name="TKey"></typeparam>
    public class FeatureSplitter<TGenerator, TKey>: IRuleGenerator where TGenerator : IRuleGenerator
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
                _protocols.Add(key, _nestedGenerator(ShortHash.HexHash(_chain + "_" + key), _table));
            }

            var gen = _protocols[key];
            
            gen.AddRule(rule);
        }

        public void Output(IpTablesSystem system, IpTablesRuleSet ruleSet)
        {
            foreach (var p in _protocols)
            {
                var description = _chain + "_" + p.Key;
                String chainName = ShortHash.HexHash(description);
                if(ruleSet.Chains.HasChain(chainName, _table))
                {
                    throw new IpTablesNetException(String.Format("Duplicate feature split: {0}", chainName));
                }

                //Jump to chain
                var chain = ruleSet.Chains.GetChainOrAdd(_chain, _table, system);
                IpTablesRule jumpRule = new IpTablesRule(system, chain);
                jumpRule.GetModuleOrLoad<CoreModule>("core").Jump = chainName;
                jumpRule.GetModuleOrLoad<CommentModule>("comment").CommentText = _commentPrefix + "|FS|" + description;
                _setter(jumpRule, p.Key);
                ruleSet.AddRule(jumpRule);

                //Nested output

                ruleSet.AddChain(chainName, _table);
                p.Value.Output(system, ruleSet);
            }
        }
    }

    public class FeatureSplitter<TGenerator> : FeatureSplitter<TGenerator, String> where TGenerator : IRuleGenerator
    {
        public FeatureSplitter(string chain, string table, Func<IpTablesRule, string> extractor, Action<IpTablesRule, string> setter, Func<string, string, TGenerator> nestedGenerator, string commentPrefix) : base(chain, table, extractor, setter, nestedGenerator, commentPrefix)
        {
        }
    }
}
