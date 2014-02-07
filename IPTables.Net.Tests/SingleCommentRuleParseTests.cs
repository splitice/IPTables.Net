using System;
using IPTables.Net.Iptables;
using NUnit.Framework;

namespace IPTables.Net.Tests
{
    [TestFixture]
    internal class SingleCommentRuleParseTests
    {
        [Test]
        public void TestDropFragmentedTcpDnsWithComment()
        {
            String rule = "-A INPUT -p tcp ! -f -j DROP -m tcp --sport 53 -m comment --comment \"this is a test rule\"";
            String chain;

            IpTablesRule irule = IpTablesRule.Parse(rule, null, out chain);

            Assert.AreEqual(rule, "-A " + chain + " " + irule.GetCommand("filter"));
        }

        [Test]
        public void TestDropFragmentedTcpDnsWithCommentEquality()
        {
            String rule = "-A INPUT -p tcp ! -f -j DROP -m tcp --sport 53 -m comment --comment \"this is a test rule\"";
            String chain;

            IpTablesRule irule1 = IpTablesRule.Parse(rule, null, out chain);
            IpTablesRule irule2 = IpTablesRule.Parse(rule, null, out chain);

            Assert.AreEqual(irule1, irule2);
        }
    }
}