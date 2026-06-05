using System;
using IPTables.Net.Iptables;

namespace IPTables.Net.Tests
{
    public class SingleStatisticParseTests
    {
        [Fact]
        public void TestEvery()
        {
            String rule = "-A FORWARD -m statistic --mode nth --every 3 --packet 1";
            IpTablesChainSet chains = new IpTablesChainSet(4);

            IpTablesRule irule = IpTablesRule.Parse(rule, null, chains, 4);

            Assert.Equal(rule, irule.GetActionCommand());
        }

        [Fact]
        public void TestRandom()
        {
            String rule = "-A CHAIN -t raw -m statistic --mode random --probability 0.04";
            IpTablesChainSet chains = new IpTablesChainSet(4);

            IpTablesRule irule = IpTablesRule.Parse(rule, null, chains, 4);

            Assert.Equal(rule, irule.GetActionCommand());
        }
        [Fact]
        public void TestRandomRounding()
        {
            String rule = "-A CHAIN -t raw -m statistic --mode random --probability 0.03999999911";
            String rule2 = "-A CHAIN -t raw -m statistic --mode random --probability 0.03999999957";
            IpTablesChainSet chains = new IpTablesChainSet(4);

            IpTablesRule irule = IpTablesRule.Parse(rule, null, chains, 4);
            IpTablesRule irule2 = IpTablesRule.Parse(rule2, null, chains, 4);

            Assert.True(irule.Compare(irule2));
        }
        [Fact]
        public void TestRandomRoundingNot()
        {
            String rule = "-A CHAIN -t raw -m statistic --mode random --probability 0.04";
            String rule2 = "-A CHAIN -t raw -m statistic --mode random --probability 0.04000000004";
            IpTablesChainSet chains = new IpTablesChainSet(4);

            IpTablesRule irule = IpTablesRule.Parse(rule, null, chains, 4);
            IpTablesRule irule2 = IpTablesRule.Parse(rule2, null, chains, 4);


            Assert.Equal(irule.GetActionCommand(), irule2.GetActionCommand());
            Assert.True(irule.Compare(irule2));
        }
        [Fact]
        public void TestRandomRounding2()
        {
            String rule = "-A CHAIN -t raw -m statistic --mode random ! --probability 0.04";
            String rule2 = "-A CHAIN -t raw -m statistic --mode random ! --probability 0.04000000004";
            IpTablesChainSet chains = new IpTablesChainSet(4);

            IpTablesRule irule = IpTablesRule.Parse(rule, null, chains, 4);
            IpTablesRule irule2 = IpTablesRule.Parse(rule2, null, chains, 4);


            Assert.Equal(irule.GetActionCommand(), irule2.GetActionCommand());
            Assert.True(irule.Compare(irule2));
        }
        [Fact]
        public void TestRandomRounding3()
        {
            String rule = "-A CHAIN -t raw -m statistic --mode random --probability 0.09000000000";
            String rule2 = "-A CHAIN -t raw -m statistic --mode random --probability 0.08999999997";
            IpTablesChainSet chains = new IpTablesChainSet(4);

            IpTablesRule irule = IpTablesRule.Parse(rule, null, chains, 4);
            IpTablesRule irule2 = IpTablesRule.Parse(rule2, null, chains, 4);


            Assert.Equal(irule.GetActionCommand(), irule2.GetActionCommand());
            Assert.True(irule.Compare(irule2));
        }
    }
}