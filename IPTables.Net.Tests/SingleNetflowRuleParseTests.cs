using System;
using IPTables.Net.Iptables;

namespace IPTables.Net.Tests
{
    public class SingleNetflowRuleParseTests
    {
        [Theory]
        [InlineData("-A INPUT -m netflow --fw_status 1 -j ACCEPT")]
        [InlineData("-A INPUT -m ctnetflow --fw_status 1 -j ACCEPT")]
        [InlineData("-A INPUT -m netflow --fw_status 65 --nf-noports -j DROP")]
        [InlineData("-A INPUT -j NETFLOW")]
        [InlineData("-A INPUT -m netflow --nf-noports -j DROP")]
        public void TestNetflowOptionRoundTrip(string rule)
        {
            RuleParseAssert.RoundTrips(rule);
        }
    }
}
