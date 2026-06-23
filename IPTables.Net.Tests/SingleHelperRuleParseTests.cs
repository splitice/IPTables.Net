using System;
using IPTables.Net.Iptables;

namespace IPTables.Net.Tests
{
    public class SingleHelperRuleParseTests
    {
        [Fact]
        public void TestNotHelper()
        {
            String rule = "-A INPUT -m helper ! --helper cba -j ACCEPT";
            IpTablesChainSet chains = new IpTablesChainSet(4);

            IpTablesRule irule = IpTablesRule.Parse(rule, null, chains, 4);

            Assert.Equal(rule, irule.GetActionCommand());
        }

        [Fact]
        public void TestHelper()
        {
            String rule = "-A INPUT -m helper ! --helper abc -j ACCEPT";
            IpTablesChainSet chains = new IpTablesChainSet(4);

            IpTablesRule irule = IpTablesRule.Parse(rule, null, chains, 4);

            Assert.Equal(rule, irule.GetActionCommand());
        }

        [Fact]
        public void TestPositiveHelperRoundTrip()
        {
            RuleParseAssert.RoundTrips("-A INPUT -m helper --helper ftp -j ACCEPT");
        }
    }
}
