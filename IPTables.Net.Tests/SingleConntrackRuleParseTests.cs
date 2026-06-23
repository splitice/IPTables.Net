using System;
using IPTables.Net.Iptables;

namespace IPTables.Net.Tests
{
    public class SingleConntrackRuleParseTests
    {
        [Fact]
        public void TestParse()
        {
            String rule1 = "-A PREROUTING -t raw -p tcp -j CT --ctevents new,destroy";
            String rule2 = "-A PREROUTING -t raw -p tcp -j CT --ctevents \"destroy, new\"";
            IpTablesChainSet chains = new IpTablesChainSet(4);

            IpTablesRule irule1 = IpTablesRule.Parse(rule1, null, chains, 4);
            IpTablesRule irule2 = IpTablesRule.Parse(rule2, null, chains, 4);

            irule2.Equals(irule1);
            Assert.True(irule2.Compare(irule1));
        }

        [Theory]
        [InlineData("-A PREROUTING -t raw -j CT --helper ftp", "-A PREROUTING -t raw -j CT --helper ftp")]
        [InlineData("-A PREROUTING -t raw -j CT --ctevents new,destroy", "-A PREROUTING -t raw -j CT --ctevents new,destroy")]
        [InlineData("-A PREROUTING -t raw -j CT --expevents related", "-A PREROUTING -t raw -j CT --expevents related")]
        [InlineData("-A PREROUTING -t raw -j CT --notrack", "-A PREROUTING -t raw -j CT --notrack")]
        [InlineData("-A PREROUTING -t raw -j CT --helper ftp --ctevents new,destroy --expevents related --notrack", "-A PREROUTING -t raw -j CT --notrack --helper ftp --ctevents new,destroy --expevents related")]
        public void TestCtTargetOptionRoundTrip(string input, string expected)
        {
            RuleParseAssert.RoundTrips(input, expected);
        }
    }
}
