using System;
using IPTables.Net.Iptables;
using NUnit.Framework;

namespace IPTables.Net.Tests
{
    [TestFixture]
    internal class SingleLengthRuleParseTests
    {
        [Test]
        public void TestLengthRange()
        {
            String rule = "-A INPUT -m length --length 10:100 -j ACCEPT";
            IpTablesChainSet chains = new IpTablesChainSet(4);

            IpTablesRule irule = IpTablesRule.Parse(rule, null, chains);

            Assert.AreEqual(rule, irule.GetActionCommand());
        }
        [Test]
        public void TestNotLengthRange()
        {
            String rule = "-A INPUT -m length ! --length 10:100 -j ACCEPT";
            IpTablesChainSet chains = new IpTablesChainSet(4);

            IpTablesRule irule = IpTablesRule.Parse(rule, null, chains);

            Assert.AreEqual(rule, irule.GetActionCommand());
        }

        [Test]
        public void TestNotLength()
        {
            String rule = "-A INPUT -m length ! --length 10 -j ACCEPT";
            IpTablesChainSet chains = new IpTablesChainSet(4);

            IpTablesRule irule = IpTablesRule.Parse(rule, null, chains);

            Assert.AreEqual(rule, irule.GetActionCommand());
        }
    }
}