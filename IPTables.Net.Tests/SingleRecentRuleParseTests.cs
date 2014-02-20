using System;
using IPTables.Net.Iptables;
using NUnit.Framework;

namespace IPTables.Net.Tests
{
    [TestFixture]
    internal class SingleRecentRuleParseTests
    {
        [Test]
        public void TestSet()
        {
            String rule = "-A ATTK_CHECK -m recent --set --name ATTK";
            IpTablesChainSet chains = new IpTablesChainSet();

            IpTablesRule irule = IpTablesRule.Parse(rule, null, chains);

            Assert.AreEqual(rule, irule.GetFullCommand());
        }

        [Test]
        public void TestUpdate()
        {
            String rule = "-A ATTK_CHECK -m recent --update --name ATTK --seconds 180 --hitcount 20 -j ATTACKED";
            IpTablesChainSet chains = new IpTablesChainSet();

            IpTablesRule irule = IpTablesRule.Parse(rule, null, chains);

            Assert.AreEqual(rule, irule.GetFullCommand());
        }
    }
}