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
            String chain;

            IpTablesRule irule = IpTablesRule.Parse(rule, null, null);

            Assert.AreEqual(rule, irule.GetFullCommand());
        }

        [Test]
        public void TestDnatRangeSourceAndEquality()
        {
            String rule = "-A POSTROUTING -t nat -d 1.1.1.1/24 -j DNAT --to-destination 2.2.2.1-2.2.2.250";
            String chain;

            IpTablesRule irule1 = IpTablesRule.Parse(rule, null, null);
            IpTablesRule irule2 = IpTablesRule.Parse(rule, null, null);

            Assert.AreEqual(irule1, irule2);
            Assert.AreEqual(rule, irule1.GetFullCommand());
            Assert.AreEqual(rule, irule2.GetFullCommand());
        }
    }
}