using System;
using IPTables.Net.Iptables;
using NUnit.Framework;

namespace IPTables.Net.Tests
{
    [TestFixture]
    internal class SingleIpSetRuleParseTests
    {
        [Test]
        public void Test1()
        {
            String rule = "-A FORWARD -m set --match-set test src";
            IpTablesChainSet chains = new IpTablesChainSet(4);

            IpTablesRule irule = IpTablesRule.Parse(rule, null, chains, 4);

            Assert.AreEqual(rule, irule.GetActionCommand());
        }

        [Test]
        public void Test2()
        {
            String rule = "-A FORWARD -m set --match-set test src --return-nomatch ! --update-counters --packets-lt 3 ! --bytes-eq 1";
            IpTablesChainSet chains = new IpTablesChainSet(4);

            IpTablesRule irule = IpTablesRule.Parse(rule, null, chains, 4);

            Assert.AreEqual(rule, irule.GetActionCommand());
        }
    }
}