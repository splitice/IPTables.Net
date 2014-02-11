using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using IPTables.Net.Iptables;
using NUnit.Framework;

namespace IPTables.Net.Tests
{
    [TestFixture]
    class IpTablesRuleSetTests
    {
        [Test]
        public void TestAddChain()
        {
            IpTablesRuleSet ruleSet = new IpTablesRuleSet(null);
            String rule = "-A INPUT -p tcp -j DROP -m connlimit --connlimit-above 10";
            IpTablesChainSet chains = new IpTablesChainSet();

            IpTablesRule irule = IpTablesRule.Parse(rule, null, chains);

            ruleSet.AddRule(irule);

            Assert.AreEqual(1, ruleSet.Chains.Count());
            Assert.AreEqual("filter", ruleSet.Chains.First().Table);
            Assert.AreEqual(1, ruleSet.Chains.First().Rules.Count());
        }

        [Test]
        public void TestAddChainTwoRules()
        {
            IpTablesRuleSet ruleSet = new IpTablesRuleSet(null);
            String rule = "-A INPUT -p tcp -j DROP -m connlimit --connlimit-above 10";
            IpTablesChainSet chains = new IpTablesChainSet();

            IpTablesRule irule = IpTablesRule.Parse(rule, null, chains);

            ruleSet.AddRule(irule);

            Assert.AreEqual(1, ruleSet.Chains.Count());
            Assert.AreEqual("filter", ruleSet.Chains.First().Table);
            Assert.AreEqual(1, ruleSet.Chains.First().Rules.Count());

            ruleSet.AddRule(irule);

            Assert.AreEqual(1, ruleSet.Chains.Count());
            Assert.AreEqual(2, ruleSet.Chains.First().Rules.Count());
        }

        [Test]
        public void TestAddChains()
        {
            IpTablesRuleSet ruleSet = new IpTablesRuleSet(null);
            String rule = "-A INPUT -p tcp -j DROP -m connlimit --connlimit-above 10";
            IpTablesChainSet chains = new IpTablesChainSet();

            IpTablesRule irule = IpTablesRule.Parse(rule, null, chains);

            ruleSet.AddRule(irule);
            
            Assert.AreEqual(1, ruleSet.Chains.Count());
            Assert.AreEqual("filter", ruleSet.Chains.First().Table);
            Assert.AreEqual(1, ruleSet.Chains.First().Rules.Count());

            rule = "-A OUTPUT -p tcp -j DROP -m connlimit --connlimit-above 10";

            irule = IpTablesRule.Parse(rule, null, chains);
            ruleSet.AddRule(irule);

            Assert.AreEqual(2, ruleSet.Chains.Count());
            Assert.AreEqual(1, ruleSet.Chains.First().Rules.Count());
            Assert.AreEqual(1, ruleSet.Chains.Skip(1).First().Rules.Count());
            Assert.AreEqual("filter", ruleSet.Chains.Skip(1).First().Table);
        }
    }
}
