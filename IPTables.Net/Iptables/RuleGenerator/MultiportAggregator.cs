using System;
using System.Collections.Generic;
using System.Diagnostics;
using IPTables.Net.Exceptions;
using IPTables.Net.Iptables.DataTypes;
using IPTables.Net.Iptables.Helpers;
using IPTables.Net.Iptables.Modules.Comment;
using IPTables.Net.Iptables.Modules.Core;
using IPTables.Net.Iptables.Modules.Multiport;
using IPTables.Net.Iptables.Modules.Tcp;
using IPTables.Net.Iptables.Modules.Udp;

namespace IPTables.Net.Iptables.RuleGenerator
{
    /// <summary>
    /// Combine multiple rules with the same protocol and different ports into the same rule.
    /// 
    /// Assumes you have many rules that the same match conditions (except the port) and the same action.
    /// 
    /// e.g
    /// 
    /// Input:
    /// iptables -A INPUT -p tcp -m tcp --dport 80 -j ACCEPT
    /// iptables -A INPUT -p tcp -m multiport --dports 90:95 -j ACCEPT
    /// 
    /// Output:
    /// iptables -A INPUT -p tcp -m multiport --dports 80,90:95 -j ACCEPT
    /// 
    /// </summary>
    /// <typeparam name="TKey"></typeparam>
    public class MultiportAggregator<TKey> : IRuleGenerator
    {
        private String _chain;
        private String _table;
        private Dictionary<TKey, List<IpTablesRule>> _rules = new Dictionary<TKey, List<IpTablesRule>>();
        private Func<IpTablesRule, TKey> _extractKey;
        private Func<IpTablesRule, PortOrRange> _extractPort;
        private Action<IpTablesRule, List<PortOrRange>> _setPort;
        private string _commentPrefix;
        private Action<IpTablesRule, TKey> _setJump;
        private string _baseRule;

        public MultiportAggregator(String chain, String table, Func<IpTablesRule, TKey> extractKey, 
            Func<IpTablesRule, PortOrRange> extractPort, Action<IpTablesRule, List<PortOrRange>> setPort, 
            Action<IpTablesRule, TKey> setJump, String commentPrefix,
            String baseRule = null)
        {
            _chain = chain;
            _table = table;
            _extractKey = extractKey;
            _extractPort = extractPort;
            _setPort = setPort;
            _setJump = setJump;
            _commentPrefix = commentPrefix;
            if (baseRule == null)
            {
                baseRule = "-A "+chain+" -t "+table;
            }
            _baseRule = baseRule;
        }

        public static void DestinationPortSetter(IpTablesRule rule, List<PortOrRange> ranges)
        {
            var protocol = rule.GetModule<CoreModule>("core").Protocol;
            if (ranges.Count == 1 && !protocol.Null && !protocol.Not)
            {
                if (protocol.Value == "tcp")
                {
                    var tcp = rule.GetModuleOrLoad<TcpModule>("tcp");
                    tcp.DestinationPort = new ValueOrNot<PortOrRange>(ranges[0]);
                }
                else
                {
                    var tcp = rule.GetModuleOrLoad<UdpModule>("udp");
                    tcp.DestinationPort = new ValueOrNot<PortOrRange>(ranges[0]);
                }
            }
            else
            {
                var multiport = rule.GetModuleOrLoad<MultiportModule>("multiport");
                multiport.DestinationPorts = new ValueOrNot<IEnumerable<PortOrRange>>(ranges);
            }
        }

        public static void SourcePortSetter(IpTablesRule rule, List<PortOrRange> ranges)
        {
            var protocol = rule.GetModule<CoreModule>("core").Protocol;
            if (ranges.Count == 1 && !protocol.Null && !protocol.Not)
            {
                if (protocol.Value == "tcp")
                {
                    var tcp = rule.GetModuleOrLoad<TcpModule>("tcp");
                    tcp.SourcePort = new ValueOrNot<PortOrRange>(ranges[0]);
                }
                else
                {
                    var tcp = rule.GetModuleOrLoad<UdpModule>("udp");
                    tcp.SourcePort = new ValueOrNot<PortOrRange>(ranges[0]);
                }
            }
            else
            {
                var multiport = rule.GetModuleOrLoad<MultiportModule>("multiport");
                multiport.SourcePorts = new ValueOrNot<IEnumerable<PortOrRange>>(ranges);
            }
        }

        private IpTablesRule OutputRulesForGroup(IpTablesRuleSet ruleSet, IpTablesSystem system, List<IpTablesRule> rules, string chainName)
        {
            if (rules.Count == 0)
            {
                return null;
            }

            int count = 0, ruleCount = 0;
            List<PortOrRange> ranges = new List<PortOrRange>();
            IpTablesRule rule1 = null;
            var firstCore = rules[0].GetModule<CoreModule>("core");
            int ruleIdx = 1;

            Action buildRule = () =>
            {
                if (ranges.Count == 0)
                {
                    throw new IpTablesNetException("this should not happen");
                }

                rule1 = IpTablesRule.Parse(_baseRule, system, ruleSet.Chains);
                var ruleCore = rule1.GetModuleOrLoad<CoreModule>("core");
                ruleCore.Protocol = firstCore.Protocol;
                if (firstCore.TargetMode == TargetMode.Goto && !String.IsNullOrEmpty(firstCore.Goto))
                {
                    ruleCore.Goto = firstCore.Goto;
                }
                else if (firstCore.TargetMode == TargetMode.Jump && !String.IsNullOrEmpty(firstCore.Jump))
                {
                    ruleCore.Jump = firstCore.Jump;
                }
                var ruleComment = rule1.GetModuleOrLoad<CommentModule>("comment");
                ruleComment.CommentText = _commentPrefix + "|" + chainName + "|" + ruleIdx;
                if (ruleCount == 0)
                {
                    rule1.Chain = ruleSet.Chains.GetChainOrDefault(_chain, _table);
                }
                else
                {
                    rule1.Chain = ruleSet.Chains.GetChainOrDefault(chainName, _table);
                }
                _setPort(rule1, new List<PortOrRange>(ranges));
                ruleSet.AddRule(rule1);
                ruleIdx++;
            };

            List<PortOrRange> exceptions = new List<PortOrRange>();
            foreach (var rule in rules)
            {
                exceptions.Add(_extractPort(rule));
            }

            exceptions.Sort((a, b) =>
            {
                if (a.IsRange() && b.IsRange() || !a.IsRange() && !b.IsRange())
                {
                    if (a.LowerPort < b.LowerPort)
                    {
                        return -1;
                    }
                    return 1;
                }
                if (a.IsRange()) return -1;
                return 1;
            });

            exceptions = PortRangeCompression.CompressRanges(exceptions);

            for (var i=0;i<exceptions.Count;i++)
            {
                var e = exceptions[i];
                if (e.IsRange())
                {
                    count += 2;
                }
                else
                {
                    count++;
                }


                if (i + 1 < exceptions.Count)
                {
                    if (count == 14 && exceptions[i+1].IsRange())
                    {
                        ruleCount++;
                        continue;
                    }
                }

                if (count == 15)
                {
                    ruleCount++;
                }
            }
            count = 0;

            foreach (var e in exceptions)
            {
                if (count == 14 && e.IsRange() || count == 15)
                {
                    buildRule();
                    count = 0;
                    ranges.Clear();
                }
                ranges.Add(e);

                if (e.IsRange())
                {
                    count += 2;
                }
                else
                {
                    count++;
                }
            }

            /*if (ranges.Count == 0)
            {
                Debug.Assert(count == 0);
                return rule1;
            }*/

            buildRule();

            if (ruleCount != 0)
            {
                return null;
            }

            return rule1;
        }

        public void AddRule(IpTablesRule rule, TKey key)
        {
            if (!_rules.ContainsKey(key))
            {
                _rules.Add(key, new List<IpTablesRule>());
            }
            _rules[key].Add(rule);
        }

        public void AddRule(IpTablesRule rule)
        {
            if (_extractKey == null)
            {
                throw new IpTablesNetException("No key extractor provided, key must hence be provided");
            }
            var key = _extractKey(rule);
            if (!_rules.ContainsKey(key))
            {
                _rules.Add(key, new List<IpTablesRule>());
            }
            _rules[key].Add(rule);
        }

        public void Output(IpTablesSystem system, IpTablesRuleSet ruleSet)
        {
            foreach (var p in _rules)
            {
                String chainName = _chain + "_" + p.Key;
                if (ruleSet.Chains.HasChain(chainName, _table))
                {
                    throw new IpTablesNetException(String.Format("Duplicate feature split: {0}", chainName));
                }

                //Jump to chain
                var chain = ruleSet.Chains.GetChainOrAdd(chainName, _table, system);

                //Nested output
                var singleRule = OutputRulesForGroup(ruleSet, system, p.Value, chainName);
                if (singleRule == null)
                {
                    if (chain.Rules.Count != 0)
                    {
                        IpTablesRule jumpRule = IpTablesRule.Parse(_baseRule, system, ruleSet.Chains);
                        _setJump(jumpRule, p.Key);
                        jumpRule.GetModuleOrLoad<CoreModule>("core").Jump = chainName;
                        jumpRule.GetModuleOrLoad<CommentModule>("comment").CommentText = _commentPrefix + "|MA|" +
                                                                                         chainName;
                        ruleSet.AddRule(jumpRule);
                    }
                }
                else
                {
                    _setJump(singleRule, p.Key);
                }
                if(chain.Rules.Count == 0)
                {
                    ruleSet.Chains.RemoveChain(chain);
                }
            }
        }
    }
}
