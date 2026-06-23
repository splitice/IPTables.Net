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

        [Theory]
        [InlineData("-A INPUT -j LOG --log-level 4", "-A INPUT -j LOG --log-level 4")]
        [InlineData("-A INPUT -j LOG --log-prefix prefix", "-A INPUT -j LOG --log-prefix prefix --log-level 7")]
        public void TestLogOptionRoundTrip(string input, string expected)
        {
            RuleParseAssert.RoundTrips(input, expected);
        }
    }
}
