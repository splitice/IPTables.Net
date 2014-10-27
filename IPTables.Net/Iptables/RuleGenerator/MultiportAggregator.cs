using System;
using System.Collections.Generic;
using IPTables.Net.Iptables.DataTypes;
using IPTables.Net.Iptables.Modules.Comment;
using IPTables.Net.Iptables.Modules.Core;
using IPTables.Net.Iptables.Modules.Multiport;
using IPTables.Net.Iptables.Modules.Tcp;

namespace IPTables.Net.Iptables.RuleGenerator
{
    class MultiportAggregator<TKey> : IRuleGenerator
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

        public MultiportAggregator(String chain, String table, Func<IpTablesRule, TKey> extractKey, Func<IpTablesRule, PortOrRange> extractPort, Action<IpTablesRule, List<PortOrRange>> setPort, String baseRule = null)
        {
            _chain = chain;
            _table = table;
            _extractKey = extractKey;
            _extractPort = extractPort;
            _setPort = setPort;
            if (baseRule == null)
            {
                baseRule = "-A "+chain+" -t "+table;
            }
            _baseRule = baseRule;
        }

        private List<PortOrRange> GetRanged(IEnumerable<PortOrRange> ranges)
        {
            List<PortOrRange> ret = new List<PortOrRange>();
            PortOrRange start = new PortOrRange(0);
            int previous = -1;
            foreach (PortOrRange current in ranges)
            {
                if (current.LowerPort == (previous + 1))
                {
                    if (start.LowerPort == 0)
                    {
                        start = new PortOrRange((uint)previous, current.UpperPort);
                    }
                }
                else
                {
                    if (start.UpperPort != 0)
                    {
                        ret.Add(new PortOrRange(start.LowerPort, (uint)previous));
                        start = new PortOrRange(0);
                    }
                    else if (previous != -1)
                    {
                        ret.Add(new PortOrRange((uint)previous));
                    }
                }
                previous = (int)current.UpperPort;
            }
            if (start.UpperPort != 0)
            {
                ret.Add(new PortOrRange(start.LowerPort, (uint)previous));
                // ReSharper disable RedundantAssignment
                start = new PortOrRange(0);
                // ReSharper restore RedundantAssignment
            }
            else if (previous != -1)
            {
                ret.Add(new PortOrRange((uint)previous));
            }
            return ret;
        }

        public static void DestinateionPortSetter(IpTablesRule rule, List<PortOrRange> ranges)
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
                    var tcp = rule.GetModuleOrLoad<TcpModule>("udp");
                    tcp.DestinationPort = new ValueOrNot<PortOrRange>(ranges[0]);
                }
            }
            else
            {
                var multiport = rule.GetModuleOrLoad<MultiportModule>("multiport");
                multiport.DestinationPorts = new ValueOrNot<IEnumerable<PortOrRange>>(ranges);
            }
        }

        private void OutputRulesForGroup(IpTablesRuleSet ruleSet, IpTablesSystem system, List<IpTablesRule> rules)
        {
            if (rules.Count == 0)
            {
                return;
            }

            int count = 0, ruleId = 0;
            List<PortOrRange> ranges = new List<PortOrRange>();

            Action buildRule = () =>
            {
                if (ranges.Count == 0)
                {
                    throw new Exception("this should not happen");
                }
                ruleId++;

                IpTablesRule rule1 = IpTablesRule.Parse(_baseRule, system, ruleSet.ChainSet);
                _setPort(rule1, ranges);
                ruleSet.AddRule(rule1);
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

            exceptions = GetRanged(exceptions);

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

            buildRule();
        }

        public void AddRule(IpTablesRule rule)
        {
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
                String chainName = _chain + "|" + p.Key;
                if (ruleSet.ChainSet.HasChain(chainName, _table))
                {
                    throw new Exception(String.Format("Duplicate feature split: {0}", chainName));
                }

                //Jump to chain
                var chain = ruleSet.ChainSet.GetChainOrAdd(chainName, _table, system);
                IpTablesRule jumpRule = new IpTablesRule(system, chain);
                jumpRule.GetModule<CoreModule>("core").Jump = chainName;
                jumpRule.GetModuleOrLoad<CommentModule>("comment").CommentText = _commentPrefix + "|MA|" + chainName;
                _setJump(jumpRule, p.Key);
                ruleSet.AddRule(jumpRule);

                //Nested output
                OutputRulesForGroup(ruleSet, system, p.Value);
            }
        }
    }
}
