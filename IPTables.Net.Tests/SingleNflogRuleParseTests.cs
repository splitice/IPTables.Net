using System;
using IPTables.Net.Iptables;

namespace IPTables.Net.Tests
{
    public class SingleNflogRuleParseTests
    {
        [Fact]
        public void TestXmark()
        {
            String rule = "-A INPUT -j NFLOG --nflog-group 30";
            IpTablesChainSet chains = new IpTablesChainSet(4);

            IpTablesRule irule = IpTablesRule.Parse(rule, null, chains, 4);

            Assert.Equal(rule, irule.GetActionCommand());
        }
    }
}