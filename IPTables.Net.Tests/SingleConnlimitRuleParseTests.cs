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
            String chain;

            IpTablesRule irule = IpTablesRule.Parse(rule, null, out chain);

            Assert.AreEqual(rule, "-A " + chain + " " + irule.GetCommand("filter"));
        }

        [Test]
        public void TestDropConnectionLimitEquality()
        {
            String rule = "-A INPUT -p tcp -j DROP -m connlimit --connlimit-above 10";
            String chain;

            IpTablesRule irule1 = IpTablesRule.Parse(rule, null, out chain);
            IpTablesRule irule2 = IpTablesRule.Parse(rule, null, out chain);

            Assert.AreEqual(irule1, irule2);
        }
    }
}