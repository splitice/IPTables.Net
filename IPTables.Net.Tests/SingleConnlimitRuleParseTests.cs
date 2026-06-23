using System;
using IPTables.Net.Iptables;

namespace IPTables.Net.Tests
{
    public class SingleConnlimitRuleParseTests
    {
        [Fact]
        public void TestDropConnectionLimit()
        {
            String rule = "-A INPUT -p tcp -j DROP -m connlimit --connlimit-above 10";
            IpTablesChainSet chains = new IpTablesChainSet(4);

            IpTablesRule irule = IpTablesRule.Parse(rule, null, chains, 4);

            Assert.Equal(rule, irule.GetActionCommand());
        }

        [Fact]
        public void TestDropConnectionLimitEquality()
        {
            String rule = "-A INPUT -p tcp -j DROP -m connlimit --connlimit-above 10";
            IpTablesChainSet chains = new IpTablesChainSet(4);

            IpTablesRule irule1 = IpTablesRule.Parse(rule, null, chains, 4);
            IpTablesRule irule2 = IpTablesRule.Parse(rule, null, chains, 4);

            Assert.True(irule2.Compare(irule1));
        }

        [Theory]
        [InlineData("-A INPUT -p tcp -m connlimit --connlimit-upto 5", "-A INPUT -p tcp -m connlimit --connlimit-upto 5")]
        [InlineData("-A INPUT -p tcp -m connlimit --connlimit-above 10 --connlimit-mask 24", "-A INPUT -p tcp -m connlimit --connlimit-above 10 --connlimit-mask 24")]
        [InlineData("-A INPUT -p tcp -m connlimit --connlimit-above 10 --connlimit-daddr", "-A INPUT -p tcp -m connlimit --connlimit-above 10 --connlimit-daddr")]
        [InlineData("-A INPUT -p tcp -m connlimit --connlimit-above 10 --connlimit-saddr", "-A INPUT -p tcp -m connlimit --connlimit-above 10")]
        public void TestConnlimitOptionRoundTrip(string input, string expected)
        {
            RuleParseAssert.RoundTrips(input, expected);
        }
    }
}
