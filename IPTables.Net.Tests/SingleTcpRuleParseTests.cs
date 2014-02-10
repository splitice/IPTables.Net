using System;
using IPTables.Net.Iptables;
using NUnit.Framework;

namespace IPTables.Net.Tests
{
    [TestFixture]
    internal class SingleTcpRuleParseTests
    {
        [Test]
        public void TestDropFragmentedTcpDns()
        {
            String rule = "-A INPUT -p tcp ! -f -j DROP -m tcp --sport 53";
            String chain;

            IpTablesRule irule = IpTablesRule.Parse(rule, null, null);

            Assert.AreEqual(rule, irule.GetFullCommand());
        }

        [Test]
        public void TestDropFragmentedTcpDnsEquality()
        {
            String rule = "-A INPUT -p tcp ! -f -j DROP -m tcp --sport 53";
            String chain;

            IpTablesRule irule1 = IpTablesRule.Parse(rule, null, null);
            IpTablesRule irule2 = IpTablesRule.Parse(rule, null, null);

            Assert.AreEqual(irule1, irule2);
        }
    }
}