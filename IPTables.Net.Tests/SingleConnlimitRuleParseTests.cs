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

            IpTablesRule irule = IpTablesRule.Parse(rule, null, null);

            Assert.AreEqual(rule, irule.GetFullCommand());
        }

        [Test]
        public void TestDropConnectionLimitEquality()
        {
            String rule = "-A INPUT -p tcp -j DROP -m connlimit --connlimit-above 10";
            String chain;

            IpTablesRule irule1 = IpTablesRule.Parse(rule, null, null);
            IpTablesRule irule2 = IpTablesRule.Parse(rule, null, null);

            Assert.AreEqual(irule1, irule2);
        }
    }
}