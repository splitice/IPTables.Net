using System;
using IPTables.Net.Iptables;
using NUnit.Framework;

namespace IPTables.Net.Tests
{
    [TestFixture]
    internal class SingleNfacctRuleParseTests
    {
        [Test]
        public void TestSmall()
        {
            String rule = "-A INPUT -j ACCEPT -m nfacct --nfacct-name test";
            IpTablesChainSet chains = new IpTablesChainSet(4);

            IpTablesRule irule = IpTablesRule.Parse(rule, null, chains, 4);

            Assert.AreEqual(rule, irule.GetActionCommand());
        }

        [Test]
        public void TestQuote()
        {
            String rule = "-A INPUT -j ACCEPT -m nfacct --nfacct-name \"test\"";
            String rule2 = "-A INPUT -j ACCEPT -m nfacct --nfacct-name test";
            IpTablesChainSet chains = new IpTablesChainSet(4);

            IpTablesRule irule = IpTablesRule.Parse(rule, null, chains, 4);

            Assert.AreEqual(rule2, irule.GetActionCommand());
            Assert.AreEqual(IpTablesRule.Parse(rule2, null, chains, 4), irule);
        }

        [Test]
        public void TestDoubleSpace()
        {
            String rule = "-A INPUT -j ACCEPT -m nfacct --nfacct-name  \"test\"";
            String rule2 = "-A INPUT -j ACCEPT -m nfacct --nfacct-name test";
            IpTablesChainSet chains = new IpTablesChainSet(4);

            IpTablesRule irule = IpTablesRule.Parse(rule, null, chains, 4);

            Assert.AreEqual(rule2, irule.GetActionCommand());
            Assert.AreEqual(IpTablesRule.Parse(rule2, null, chains, 4), irule);
        }
    }
}