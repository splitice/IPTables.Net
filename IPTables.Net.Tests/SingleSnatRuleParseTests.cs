using System;
using IPTables.Net.Iptables;
using NUnit.Framework;

namespace IPTables.Net.Tests
{
    [TestFixture]
    internal class SingleSnatRuleParseTests
    {
        [Test]
        public void TestSnatSingleSource()
        {
            String rule = "-A POSTROUTING -t nat -s 1.1.1.1/24 -j SNAT --to-source 2.2.2.2";
            IpTablesChainSet chains = new IpTablesChainSet(4);

            IpTablesRule irule = IpTablesRule.Parse(rule, null, chains, 4);

            Assert.AreEqual(rule, irule.GetActionCommand());
        }

        [Test]
        public void TestSnatRangeSourceAndEquality()
        {
            String rule = "-A POSTROUTING -t nat -s 1.1.1.1/24 -j SNAT --to-source 2.2.2.1-2.2.2.250";
            IpTablesChainSet chains = new IpTablesChainSet(4);

            IpTablesRule irule1 = IpTablesRule.Parse(rule, null, chains, 4);
            IpTablesRule irule2 = IpTablesRule.Parse(rule, null, chains, 4);

            Assert.IsTrue(irule2.Compare(irule1));
            Assert.AreEqual(rule, irule1.GetActionCommand());
            Assert.AreEqual(rule, irule2.GetActionCommand());
        }
    }
}