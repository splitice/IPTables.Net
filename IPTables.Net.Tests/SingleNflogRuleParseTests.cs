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

        [Theory]
        [InlineData("-A INPUT -j NFLOG --nflog-prefix 'prefix text'", "-A INPUT -j NFLOG --nflog-prefix 'prefix text'")]
        [InlineData("-A INPUT -j NFLOG --nflog-range 128", "-A INPUT -j NFLOG --nflog-range 128")]
        [InlineData("-A INPUT -j NFLOG --nflog-threshold 10", "-A INPUT -j NFLOG --nflog-threshold 10")]
        [InlineData("-A INPUT -j NFLOG --nflog-group 30 --nflog-prefix 'prefix text' --nflog-range 128 --nflog-threshold 10", "-A INPUT -j NFLOG --nflog-group 30 --nflog-prefix 'prefix text' --nflog-range 128 --nflog-threshold 10")]
        public void TestNflogOptionRoundTrip(string input, string expected)
        {
            RuleParseAssert.RoundTrips(input, expected);
        }
    }
}
