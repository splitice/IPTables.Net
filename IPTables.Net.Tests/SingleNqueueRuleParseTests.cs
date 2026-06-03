using System;
using IPTables.Net.Iptables;

namespace IPTables.Net.Tests
{
    public class SingleNqueueRuleParseTests
    {
        [Fact]
        public void TestXmark()
        {
            String rule = "-A INPUT -j NFQUEUE --queue-num 1 --queue-bypass";
            IpTablesChainSet chains = new IpTablesChainSet(4);

            IpTablesRule irule = IpTablesRule.Parse(rule, null, chains, 4);

            Assert.Equal(rule, irule.GetActionCommand());
        }
    }
}