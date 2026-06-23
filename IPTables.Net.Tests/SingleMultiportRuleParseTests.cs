using System;
using IPTables.Net.Iptables;

namespace IPTables.Net.Tests
{
    public class SingleMultiportRuleParseTests
    {
        [Fact]
        public void TestMultiports()
        {
            String rule = "-A INPUT -p tcp -m multiport --ports 80,1000:1080";
            IpTablesChainSet chains = new IpTablesChainSet(4);

            IpTablesRule irule = IpTablesRule.Parse(rule, null, chains, 4);

            Assert.Equal(rule, irule.GetActionCommand());
        }
        [Fact]
        public void TestDestinationMultiports()
        {
            String rule = "-A INPUT -p tcp -m multiport --sports 80,1000:1080";
            IpTablesChainSet chains = new IpTablesChainSet(4);

            IpTablesRule irule = IpTablesRule.Parse(rule, null, chains, 4);

            Assert.Equal(rule, irule.GetActionCommand());
        }
        [Fact]
        public void TestSourceMultiports()
        {
            String rule = "-A INPUT -p tcp -m multiport --dports 80,1000:1080";
            IpTablesChainSet chains = new IpTablesChainSet(4);

            IpTablesRule irule = IpTablesRule.Parse(rule, null, chains, 4);

            Assert.Equal(rule, irule.GetActionCommand());
        }

        [Fact]
        public void TesNottMultiports()
        {
            String rule = "-A INPUT -p tcp -m multiport ! --ports 80,1000:1080";
            IpTablesChainSet chains = new IpTablesChainSet(4);

            IpTablesRule irule = IpTablesRule.Parse(rule, null, chains, 4);

            Assert.Equal(rule, irule.GetActionCommand());
        }
        [Fact]
        public void TestDestinationNotMultiports()
        {
            String rule = "-A INPUT -p tcp -m multiport ! --sports 80,1000:1080";
            IpTablesChainSet chains = new IpTablesChainSet(4);

            IpTablesRule irule = IpTablesRule.Parse(rule, null, chains, 4);

            Assert.Equal(rule, irule.GetActionCommand());
        }
        [Fact]
        public void TestSourceNotMultiports()
        {
            String rule = "-A INPUT -p tcp -m multiport ! --dports 80,1000:1080";
            IpTablesChainSet chains = new IpTablesChainSet(4);

            IpTablesRule irule = IpTablesRule.Parse(rule, null, chains, 4);

            Assert.Equal(rule, irule.GetActionCommand());
        }

        [Theory]
        [InlineData("-A INPUT -p tcp -m multiport --ports 80,1000:1080", "-A INPUT -p tcp -m multiport --ports 80,1000:1080")]
        [InlineData("-A INPUT -p tcp -m multiport --sports 80,1000:1080", "-A INPUT -p tcp -m multiport --sports 80,1000:1080")]
        [InlineData("-A INPUT -p tcp -m multiport --dports 80,1000:1080", "-A INPUT -p tcp -m multiport --dports 80,1000:1080")]
        [InlineData("-A INPUT -p tcp -m multiport ! --ports 80,1000:1080", "-A INPUT -p tcp -m multiport ! --ports 80,1000:1080")]
        [InlineData("-A INPUT -p tcp -m multiport ! --sports 80,1000:1080", "-A INPUT -p tcp -m multiport ! --sports 80,1000:1080")]
        [InlineData("-A INPUT -p tcp -m multiport ! --dports 80,1000:1080", "-A INPUT -p tcp -m multiport ! --dports 80,1000:1080")]
        [InlineData("-A INPUT -p tcp -m multiport --source-ports 80,1000:1080", "-A INPUT -p tcp -m multiport --sports 80,1000:1080")]
        [InlineData("-A INPUT -p tcp -m multiport --destination-ports 80,1000:1080", "-A INPUT -p tcp -m multiport --dports 80,1000:1080")]
        [InlineData("-A INPUT -p tcp -m multiport ! --source-ports 80,1000:1080", "-A INPUT -p tcp -m multiport ! --sports 80,1000:1080")]
        [InlineData("-A INPUT -p tcp -m multiport ! --destination-ports 80,1000:1080", "-A INPUT -p tcp -m multiport ! --dports 80,1000:1080")]
        public void TestMultiportLongAliasRoundTrip(string input, string expected)
        {
            RuleParseAssert.RoundTrips(input, expected);
        }
    }
}
