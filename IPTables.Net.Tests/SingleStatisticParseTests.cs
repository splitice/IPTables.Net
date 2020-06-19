using System;
using IPTables.Net.Iptables;
using NUnit.Framework;

namespace IPTables.Net.Tests
{
    [TestFixture]
    internal class SingleStatisticParseTests
    {
        [Test]
        public void TestEvery()
        {
            String rule = "-A FORWARD -m statistic --mode nth --every 3 --packet 1";
            IpTablesChainSet chains = new IpTablesChainSet(4);

            IpTablesRule irule = IpTablesRule.Parse(rule, null, chains, 4);

            Assert.AreEqual(rule, irule.GetActionCommand());
        }

        [Test]
        public void TestRandom()
        {
            String rule = "-A CHAIN -t raw -m statistic --mode random --probability 0.04000000000";
            IpTablesChainSet chains = new IpTablesChainSet(4);

            IpTablesRule irule = IpTablesRule.Parse(rule, null, chains, 4);

            Assert.AreEqual(rule, irule.GetActionCommand());
        }
        [Test]
        public void TestRandomRounding()
        {
            String rule = "-A CHAIN -t raw -m statistic --mode random --probability 0.03999999911";
            String rule2 = "-A CHAIN -t raw -m statistic --mode random --probability 0.03999999957";
            IpTablesChainSet chains = new IpTablesChainSet(4);

            IpTablesRule irule = IpTablesRule.Parse(rule, null, chains, 4);
            IpTablesRule irule2 = IpTablesRule.Parse(rule2, null, chains, 4);

            Assert.IsTrue(irule.Compare(irule2));
        }
        [Test]
        public void TestRandomRounding2()
        {
            String rule = "-A CHAIN -t raw -m statistic --mode random --probability 0.04";
            String rule2 = "-A CHAIN -t raw -m statistic --mode random --probability 0.04000000004";
            IpTablesChainSet chains = new IpTablesChainSet(4);

            IpTablesRule irule = IpTablesRule.Parse(rule, null, chains, 4);
            IpTablesRule irule2 = IpTablesRule.Parse(rule2, null, chains, 4);


            Assert.AreEqual(irule.GetActionCommand(), irule2.GetActionCommand());
            Assert.IsTrue(irule.Compare(irule2));
        }
    }
}