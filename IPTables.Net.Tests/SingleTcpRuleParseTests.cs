using System;
using IPTables.Net.Iptables;

namespace IPTables.Net.Tests
{
    public class SingleTcpRuleParseTests
    {
        [Fact]
        public void TestDropFragmentedTcpDns()
        {
            String rule = "-A INPUT -p tcp ! -f -j DROP -m tcp --sport 53";
            IpTablesChainSet chains = new IpTablesChainSet(4);

            IpTablesRule irule = IpTablesRule.Parse(rule, null, chains, 4);

            Assert.Equal(rule, irule.GetActionCommand());
        }

        [Fact]
        public void TestDropFragmentedTcpDnsEquality()
        {
            String rule = "-A INPUT -p tcp ! -f -j DROP -m tcp --sport 53";
            IpTablesChainSet chains = new IpTablesChainSet(4);

            IpTablesRule irule1 = IpTablesRule.Parse(rule, null, chains, 4);
            IpTablesRule irule2 = IpTablesRule.Parse(rule, null, chains, 4);

            Assert.True(irule2.Compare(irule1));
        }

        [Fact]
        public void TestCoreSportEquality()
        {
            String rule = "-A INPUT -p tcp -j DROP -m tcp --sport 1";
            IpTablesChainSet chains = new IpTablesChainSet(4);

            IpTablesRule irule1 = IpTablesRule.Parse(rule, null, chains, 4);
            IpTablesRule irule2 = IpTablesRule.Parse(rule, null, chains, 4);

            Assert.True(irule2.Compare(irule1));
        }

        [Fact]
        public void TestCoreSportZeroValue()
        {
            String rule = "-A INPUT -p tcp -j DROP -m tcp --sport 0";
            IpTablesChainSet chains = new IpTablesChainSet(4);

            IpTablesRule irule1 = IpTablesRule.Parse(rule, null, chains, 4);

            Assert.Equal(rule, irule1.GetActionCommand());
        }

        [Theory]
        [InlineData("-A INPUT -p tcp -m tcp --source-port 1000:2000", "-A INPUT -p tcp -m tcp --sport 1000:2000")]
        [InlineData("-A INPUT -p tcp -m tcp ! --source-port 1000:2000", "-A INPUT -p tcp -m tcp ! --sport 1000:2000")]
        [InlineData("-A INPUT -p tcp -m tcp --destination-port 443", "-A INPUT -p tcp -m tcp --dport 443")]
        [InlineData("-A INPUT -p tcp -m tcp ! --destination-port 443", "-A INPUT -p tcp -m tcp ! --dport 443")]
        [InlineData("-A INPUT -p tcp -m tcp --tcp-flags SYN,ACK SYN", "-A INPUT -p tcp -m tcp --tcp-flags SYN,ACK SYN")]
        [InlineData("-A INPUT -p tcp -m tcp ! --tcp-flags SYN,ACK SYN", "-A INPUT -p tcp -m tcp ! --tcp-flags SYN,ACK SYN")]
        [InlineData("-A INPUT -p tcp -m tcp --tcp-option 2", "-A INPUT -p tcp -m tcp --tcp-option 2")]
        [InlineData("-A INPUT -p tcp -m tcp ! --tcp-option 2", "-A INPUT -p tcp -m tcp ! --tcp-option 2")]
        public void TestTcpOptionRoundTrip(string input, string expected)
        {
            RuleParseAssert.RoundTrips(input, expected);
        }

        [Fact]
        public void TestTcpSynAliasRoundTrip()
        {
            RuleParseAssert.RoundTrips(
                "-A INPUT -p tcp -m tcp --syn",
                "-A INPUT -p tcp -m tcp --tcp-flags SYN,RST,ACK,FIN SYN");
        }
    }
}
