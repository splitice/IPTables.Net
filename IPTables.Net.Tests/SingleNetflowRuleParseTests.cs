using System;
using IPTables.Net.Iptables;

namespace IPTables.Net.Tests
{
    public class SingleNetflowRuleParseTests
    {
        [Fact]
        public void TestFwmark()
        {
            String rule = "-A INPUT -m netflow --fw_status 1 -j ACCEPT";
            IpTablesChainSet chains = new IpTablesChainSet(4);

            IpTablesRule irule = IpTablesRule.Parse(rule, null, chains, 4);

            Assert.Equal(rule, irule.GetActionCommand());
        }
        [Fact]
        public void TestFwmarkCt()
        {
            String rule = "-A INPUT -m ctnetflow --fw_status 1 -j ACCEPT";
            IpTablesChainSet chains = new IpTablesChainSet(4);

            IpTablesRule irule = IpTablesRule.Parse(rule, null, chains, 4);

            Assert.Equal(rule, irule.GetActionCommand());
        }


        [Fact]
        public void TestNoPorts()
        {
            String rule = "-A INPUT -m netflow --fw_status 65 --nf-noports -j DROP";
            IpTablesChainSet chains = new IpTablesChainSet(4);

            IpTablesRule irule = IpTablesRule.Parse(rule, null, chains, 4);

            Assert.Equal(rule, irule.GetActionCommand());
        }
    }
}