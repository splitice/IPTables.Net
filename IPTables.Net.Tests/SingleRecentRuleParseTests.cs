using System;
using IPTables.Net.Iptables;

namespace IPTables.Net.Tests
{
    public class SingleRecentRuleParseTests
    {
        [Fact]
        public void TestSet()
        {
            String rule = "-A ATTK_CHECK -m recent --set --name ATTK";
            IpTablesChainSet chains = new IpTablesChainSet(4);

            IpTablesRule irule = IpTablesRule.Parse(rule, null, chains, 4);

            Assert.Equal(rule, irule.GetActionCommand());
        }

        [Fact]
        public void TestUpdate()
        {
            String rule = "-A ATTK_CHECK -m recent --update --name ATTK --seconds 180 --hitcount 20 -j ATTACKED";
            IpTablesChainSet chains = new IpTablesChainSet(4);

            IpTablesRule irule = IpTablesRule.Parse(rule, null, chains, 4);

            Assert.Equal(rule, irule.GetActionCommand());
        }

        [Fact]
        public void TestCompare1()
        {
            String rule = "-A ATTK_CHECK -m recent --rcheck --name BANNED --seconds 180 --reap --rttl -j ATTACKED";
            IpTablesChainSet chains = new IpTablesChainSet(4);

            Assert.True(IpTablesRule.Parse(rule, null, chains, 4).Compare(IpTablesRule.Parse(rule, null, chains, 4)));
        }
    }
}