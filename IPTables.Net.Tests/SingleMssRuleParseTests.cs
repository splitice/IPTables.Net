using System;
using IPTables.Net.Iptables;

namespace IPTables.Net.Tests
{
    public class SingleMssRuleParseTests
    {
        [Fact]
        public void TestMssRange()
        {
            String rule = "-A INPUT -m tcpmss --mss 10:100 -j ACCEPT";
            IpTablesChainSet chains = new IpTablesChainSet(4);

            IpTablesRule irule = IpTablesRule.Parse(rule, null, chains, 4);

            Assert.Equal(rule, irule.GetActionCommand());
        }
        [Fact]
        public void TestMssWithSetMssRange()
        {
            String rule = "-A INPUT -m tcpmss --mss 10:100 -j TCPMSS --set-mss 1000";
            IpTablesChainSet chains = new IpTablesChainSet(4);

            IpTablesRule irule = IpTablesRule.Parse(rule, null, chains, 4);

            Assert.Equal(rule, irule.GetActionCommand());
        }

        [Theory]
        [InlineData("-A INPUT -m tcpmss ! --mss 536:1460 -j ACCEPT")]
        [InlineData("-A INPUT -j TCPMSS --clamp-mss-to-pmtu")]
        [InlineData("-A INPUT -j TCPMSS --set-mss 1200")]
        public void TestMssOptionRoundTrip(string rule)
        {
            RuleParseAssert.RoundTrips(rule);
        }
    }
}
