using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using IPTables.Net.Iptables;

namespace IPTables.Net.Tests
{
    public class IpTablesRuleSetTests
    {
        [Fact]
        public void TestAddChain()
        {
            IpTablesRuleSet ruleSet = new IpTablesRuleSet(4,null);
            String rule = "-A INPUT -p tcp -j DROP -m connlimit --connlimit-above 10";
            IpTablesChainSet chains = new IpTablesChainSet(4);

            IpTablesRule irule = IpTablesRule.Parse(rule, null, chains, 4);

            ruleSet.AddRule(irule);

            Assert.Equal(1, ruleSet.Chains.Count());
            Assert.Equal("filter", ruleSet.Chains.First().Table);
            Assert.Equal(1, ruleSet.Chains.First().Rules.Count());
        }

        [Fact]
        public void TestAddChainTwoRules()
        {
            IpTablesRuleSet ruleSet = new IpTablesRuleSet(4,null);
            String rule = "-A INPUT -p tcp -j DROP -m connlimit --connlimit-above 10";
            IpTablesChainSet chains = new IpTablesChainSet(4);

            IpTablesRule irule = IpTablesRule.Parse(rule, null, chains, 4);

            ruleSet.AddRule(irule);

            Assert.Equal(1, ruleSet.Chains.Count());
            Assert.Equal("filter", ruleSet.Chains.First().Table);
            Assert.Equal(1, ruleSet.Chains.First().Rules.Count());

            ruleSet.AddRule(irule);

            Assert.Equal(1, ruleSet.Chains.Count());
            Assert.Equal(2, ruleSet.Chains.First().Rules.Count());
        }

        [Fact]
        public void TestAddChains()
        {
            IpTablesRuleSet ruleSet = new IpTablesRuleSet(4,null);
            String rule = "-A INPUT -p tcp -j DROP -m connlimit --connlimit-above 10";
            IpTablesChainSet chains = new IpTablesChainSet(4);

            IpTablesRule irule = IpTablesRule.Parse(rule, null, chains, 4);

            ruleSet.AddRule(irule);

            Assert.Equal(1, ruleSet.Chains.Count());
            Assert.Equal("filter", ruleSet.Chains.First().Table);
            Assert.Equal(1, ruleSet.Chains.First().Rules.Count());

            rule = "-A OUTPUT -p tcp -j DROP -m connlimit --connlimit-above 10";

            irule = IpTablesRule.Parse(rule, null, chains, 4);
            ruleSet.AddRule(irule);

            Assert.Equal(2, ruleSet.Chains.Count());
            Assert.Equal(1, ruleSet.Chains.First().Rules.Count());
            Assert.Equal(1, ruleSet.Chains.Skip(1).First().Rules.Count());
            Assert.Equal("filter", ruleSet.Chains.Skip(1).First().Table);
        }
    }
}
