using System;
using IPTables.Net.Iptables;

namespace IPTables.Net.Tests
{
    public class SingleRejectTargetTests
    {
        [Fact]
        public void TestRejectWithIcmp()
        {
            String rule = "-A ufw-user-limit -j REJECT --reject-with icmp-port-unreachable";
            IpTablesChainSet chains = new IpTablesChainSet(4);

            IpTablesRule irule = IpTablesRule.Parse(rule, null, chains, 4);

            Assert.Equal(rule, irule.GetActionCommand());
        }

        [Fact]
        public void TestRejectRoundTrip()
        {
            RuleParseAssert.RoundTrips("-A ufw-user-limit -j REJECT --reject-with icmp-port-unreachable");
        }
    }
}
