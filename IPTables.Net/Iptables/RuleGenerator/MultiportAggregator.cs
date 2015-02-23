using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
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
        private Action<IpTablesRule, TKey> _setKey;

        public MultiportAggregator(String chain, String table, Func<IpTablesRule, TKey> extractKey, 
            Func<IpTablesRule, PortOrRange> extractPort, Action<IpTablesRule, List<PortOrRange>> setPort, 
            Action<IpTablesRule, TKey> setJump, String commentPrefix,
            String baseRule = null, Action<IpTablesRule, TKey> setKey = null)
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
            _setKey = setKey;
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

        private IpTablesRule OutputRulesForGroup(IpTablesRuleSet ruleSet, IpTablesSystem system, List<IpTablesRule> rules, string chainName, TKey key)
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

                //Core Module
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

                //Comment Module
                var ruleComment = rule1.GetModuleOrLoad<CommentModule>("comment");
                ruleComment.CommentText = _commentPrefix + "|" + chainName + "|" + ruleIdx;

                // Create just one rule if there is only one set of multiports
                if (ruleCount == 1 && _setKey != null)
                {
                    _setKey(rule1, key);
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

            List<PortOrRange> ports = rules.Select(rule => _extractPort(rule)).ToList();
            PortRangeHelpers.SortRangeFirstLowHigh(ports);
            ports = PortRangeHelpers.CompressRanges(ports);
            ruleCount = PortRangeHelpers.CountRequiredMultiports(ports);
            
            foreach (var e in ports)
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

            if (ranges.Count != 0)
            {
                buildRule();
            }

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
                var singleRule = OutputRulesForGroup(ruleSet, system, p.Value, chainName, p.Key);
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
