using System;
using IPTables.Net.Iptables;

namespace IPTables.Net.Tests
{
    public class SingleSnatRuleParseTests
    {
        [Fact]
        public void TestSnatSingleSource()
        {
            String rule = "-A POSTROUTING -t nat -s 1.1.1.1/24 -j SNAT --to-source 2.2.2.2";
            IpTablesChainSet chains = new IpTablesChainSet(4);

            IpTablesRule irule = IpTablesRule.Parse(rule, null, chains, 4);

            Assert.Equal(rule, irule.GetActionCommand());
        }

        [Fact]
        public void TestSnatRangeSourceAndEquality()
        {
            String rule = "-A POSTROUTING -t nat -s 1.1.1.1/24 -j SNAT --to-source 2.2.2.1-2.2.2.250";
            IpTablesChainSet chains = new IpTablesChainSet(4);

            IpTablesRule irule1 = IpTablesRule.Parse(rule, null, chains, 4);
            IpTablesRule irule2 = IpTablesRule.Parse(rule, null, chains, 4);

            Assert.True(irule2.Compare(irule1));
            Assert.Equal(rule, irule1.GetActionCommand());
            Assert.Equal(rule, irule2.GetActionCommand());
        }

        [Theory]
        [InlineData("-A POSTROUTING -t nat -j SNAT --to-source 2.2.2.2:1000-2000")]
        [InlineData("-A POSTROUTING -t nat -j SNAT --random")]
        [InlineData("-A POSTROUTING -t nat -j SNAT --persistent")]
        [InlineData("-A POSTROUTING -t nat -j SNAT --to-source 2.2.2.2 --random --persistent")]
        public void TestSnatOptionRoundTrip(string rule)
        {
            RuleParseAssert.RoundTrips(rule);
        }
    }
}
