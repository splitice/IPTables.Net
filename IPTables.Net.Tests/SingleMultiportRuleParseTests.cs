using System;
using IPTables.Net.Iptables;
using NUnit.Framework;

namespace IPTables.Net.Tests
{
    [TestFixture]
    internal class SingleMultiportRuleParseTests
    {
        [Test]
        public void TestMultiports()
        {
            String rule = "-A INPUT -p tcp -m multiport --ports 80,1000:1080";
            IpTablesChainSet chains = new IpTablesChainSet(4);

            IpTablesRule irule = IpTablesRule.Parse(rule, null, chains, 4);

            Assert.AreEqual(rule, irule.GetActionCommand());
        }
        [Test]
        public void TestDestinationMultiports()
        {
            String rule = "-A INPUT -p tcp -m multiport --sports 80,1000:1080";
            IpTablesChainSet chains = new IpTablesChainSet(4);

            IpTablesRule irule = IpTablesRule.Parse(rule, null, chains, 4);

            Assert.AreEqual(rule, irule.GetActionCommand());
        }
        [Test]
        public void TestSourceMultiports()
        {
            String rule = "-A INPUT -p tcp -m multiport --dports 80,1000:1080";
            IpTablesChainSet chains = new IpTablesChainSet(4);

            IpTablesRule irule = IpTablesRule.Parse(rule, null, chains, 4);

            Assert.AreEqual(rule, irule.GetActionCommand());
        }

        [Test]
        public void TesNottMultiports()
        {
            String rule = "-A INPUT -p tcp -m multiport ! --ports 80,1000:1080";
            IpTablesChainSet chains = new IpTablesChainSet(4);

            IpTablesRule irule = IpTablesRule.Parse(rule, null, chains, 4);

            Assert.AreEqual(rule, irule.GetActionCommand());
        }
        [Test]
        public void TestDestinationNotMultiports()
        {
            String rule = "-A INPUT -p tcp -m multiport ! --sports 80,1000:1080";
            IpTablesChainSet chains = new IpTablesChainSet(4);

            IpTablesRule irule = IpTablesRule.Parse(rule, null, chains, 4);

            Assert.AreEqual(rule, irule.GetActionCommand());
        }
        [Test]
        public void TestSourceNotMultiports()
        {
            String rule = "-A INPUT -p tcp -m multiport ! --dports 80,1000:1080";
            IpTablesChainSet chains = new IpTablesChainSet(4);

            IpTablesRule irule = IpTablesRule.Parse(rule, null, chains, 4);

            Assert.AreEqual(rule, irule.GetActionCommand());
        }
    }
}