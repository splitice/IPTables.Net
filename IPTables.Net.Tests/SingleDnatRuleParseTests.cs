using System;
using IPTables.Net.Iptables;
using NUnit.Framework;

namespace IPTables.Net.Tests
{
    [TestFixture]
    internal class SingleDnatRuleParseTests
    {
        [Test]
        public void TestDnatSingleSource()
        {
            String rule = "-A PREROUTING -t nat -d 1.1.1.1/24 -j DNAT --to-destination 2.2.2.2";
            IpTablesChainSet chains = new IpTablesChainSet();

            IpTablesRule irule = IpTablesRule.Parse(rule, null, chains);

            Assert.AreEqual(rule, irule.GetActionCommandParamters());
        }

        [Test]
        public void TestDnatRangeSourceAndEquality()
        {
            String rule = "-A POSTROUTING -t nat -d 1.1.1.1/24 -j DNAT --to-destination 2.2.2.1-2.2.2.250";
            IpTablesChainSet chains = new IpTablesChainSet();

            IpTablesRule irule1 = IpTablesRule.Parse(rule, null, chains);
            IpTablesRule irule2 = IpTablesRule.Parse(rule, null, chains);

            Assert.AreEqual(irule1, irule2);
            Assert.AreEqual(rule, irule1.GetActionCommandParamters());
            Assert.AreEqual(rule, irule2.GetActionCommandParamters());
        }
    }
}