using System;
using IPTables.Net.Iptables;

namespace IPTables.Net.Tests
{
    public class SingleIpSetRuleParseTests
    {
        [Fact]
        public void Test1()
        {
            String rule = "-A FORWARD -m set --match-set test src";
            IpTablesChainSet chains = new IpTablesChainSet(4);

            IpTablesRule irule = IpTablesRule.Parse(rule, null, chains, 4);

            Assert.Equal(rule, irule.GetActionCommand());
        }

        [Fact]
        public void Test2()
        {
            String rule = "-A FORWARD -m set --match-set test src --return-nomatch ! --update-counters --packets-lt 3 ! --bytes-eq 1";
            IpTablesChainSet chains = new IpTablesChainSet(4);

            IpTablesRule irule = IpTablesRule.Parse(rule, null, chains, 4);

            Assert.Equal(rule, irule.GetActionCommand());
        }
    }
}