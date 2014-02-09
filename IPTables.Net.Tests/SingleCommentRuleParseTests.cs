using System;
using IPTables.Net.Iptables;
using IPTables.Net.Iptables.Modules.Comment;
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

        [Test]
        public void TestAddCommentAfter()
        {
            String rule1 = "-A INPUT -p tcp ! -f -j DROP -m tcp --sport 53";
            String rule2 = "-A INPUT -p tcp ! -f -j DROP -m tcp --sport 53 -m comment --comment \"this is a test rule\"";
            String chain;

            IpTablesRule irule1 = IpTablesRule.Parse(rule1, null, out chain);
            irule1.SetComment("this is a test rule");

            Assert.AreEqual(rule2, "-A " + chain + " " + irule1.GetCommand("filter"));
        }
    }
}