using System;
using IPTables.Net.Iptables;

namespace IPTables.Net.Tests
{
    public class SingleLogRuleParseTests
    {
        [Fact]
        public void TestLogWithPrefix()
        {
            String rule = "-A INPUT -j LOG --log-prefix 'IPTABLES (Rule ATTACKED): ' --log-level 7";
            IpTablesChainSet chains = new IpTablesChainSet(4);

            IpTablesRule irule = IpTablesRule.Parse(rule, null, chains, 4);

            Assert.Equal(rule, irule.GetActionCommand());
        }
    }
}