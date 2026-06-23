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

        [Theory]
        [InlineData("-A FORWARD -m set ! --match-set test src", "-A FORWARD -m set ! --match-set test src")]
        [InlineData("-A FORWARD -m set --match-set test src --return-nomatch", "-A FORWARD -m set --match-set test src --return-nomatch")]
        [InlineData("-A FORWARD -m set --match-set test src ! --update-counters", "-A FORWARD -m set --match-set test src ! --update-counters")]
        [InlineData("-A FORWARD -m set --match-set test src ! --update-subcounters", "-A FORWARD -m set --match-set test src ! --update-subcounters")]
        [InlineData("-A FORWARD -m set --match-set test src --packets-eq 3", "-A FORWARD -m set --match-set test src --packets-eq 3")]
        [InlineData("-A FORWARD -m set --match-set test src ! --packets-eq 3", "-A FORWARD -m set --match-set test src ! --packets-eq 3")]
        [InlineData("-A FORWARD -m set --match-set test src --packets-lt 3", "-A FORWARD -m set --match-set test src --packets-lt 3")]
        [InlineData("-A FORWARD -m set --match-set test src --packets-gt 3", "-A FORWARD -m set --match-set test src --packets-gt 3")]
        [InlineData("-A FORWARD -m set --match-set test src --bytes-eq 4", "-A FORWARD -m set --match-set test src --bytes-eq 4")]
        [InlineData("-A FORWARD -m set --match-set test src ! --bytes-eq 4", "-A FORWARD -m set --match-set test src ! --bytes-eq 4")]
        [InlineData("-A FORWARD -m set --match-set test src --bytes-lt 4", "-A FORWARD -m set --match-set test src --bytes-lt 4")]
        [InlineData("-A FORWARD -m set --match-set test src --bytes-gt 4", "-A FORWARD -m set --match-set test src --bytes-gt 4")]
        public void TestSetMatchOptionRoundTrip(string input, string expected)
        {
            RuleParseAssert.RoundTrips(input, expected);
        }

        [Theory]
        [InlineData("-A FORWARD -j SET --add-set test src", "-A FORWARD -j SET --add-set test src")]
        [InlineData("-A FORWARD -j SET --del-set test dst", "-A FORWARD -j SET --del-set test dst")]
        [InlineData("-A FORWARD -j SET --map-set test src,dst", "-A FORWARD -j SET --map-set test src,dst")]
        [InlineData("-A FORWARD -j SET --add-set test src --exist", "-A FORWARD -j SET --add-set test src --exist")]
        [InlineData("-A FORWARD -j SET --add-set test src --timeout 30", "-A FORWARD -j SET --add-set test src --timeout 30")]
        public void TestSetTargetOptionRoundTrip(string input, string expected)
        {
            RuleParseAssert.RoundTrips(input, expected);
        }
    }
}
