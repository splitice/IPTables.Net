using System;
using IPTables.Net.Iptables;
using NUnit.Framework;

namespace IPTables.Net.Tests
{
    [TestFixture]
    internal class SingleConnlimitRuleParseTests
    {
        [Test]
        public void TestDropConnectionLimit()
        {
            String rule = "-A INPUT -p tcp -j DROP -m connlimit --connlimit-above 10";
            IpTablesChainSet chains = new IpTablesChainSet(4);

            IpTablesRule irule = IpTablesRule.Parse(rule, null, chains, 4);

            Assert.AreEqual(rule, irule.GetActionCommand());
        }

        [Test]
        public void TestDropConnectionLimitEquality()
        {
            String rule = "-A INPUT -p tcp -j DROP -m connlimit --connlimit-above 10";
            IpTablesChainSet chains = new IpTablesChainSet(4);

            IpTablesRule irule1 = IpTablesRule.Parse(rule, null, chains, 4);
            IpTablesRule irule2 = IpTablesRule.Parse(rule, null, chains, 4);

            Assert.IsTrue(irule2.Compare(irule1));
        }
    }
}