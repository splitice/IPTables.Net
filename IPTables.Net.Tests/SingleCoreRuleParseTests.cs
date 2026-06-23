using System;
using IPTables.Net.Iptables;

namespace IPTables.Net.Tests
{
    public class SingleCoreRuleParseTests
    {
        [Fact]
        public void TestCoreDropingDestination()
        {
            String rule = "-A INPUT -d 1.2.3.4/16 -j DROP";
            IpTablesChainSet chains = new IpTablesChainSet(4);

            IpTablesRule irule = IpTablesRule.Parse(rule, null, chains, 4);

            Assert.Equal(rule, irule.GetActionCommand());
        }

        [Fact]
        public void TestCoreDropingInterface()
        {
            String rule = "-A INPUT -i eth0 -j DROP";
            IpTablesChainSet chains = new IpTablesChainSet(4);

            IpTablesRule irule = IpTablesRule.Parse(rule, null, chains, 4);

            Assert.Equal(rule, irule.GetActionCommand());
        }

        [Fact]
        public void TestCoreDropingSource()
        {
            String rule = "-A INPUT -s 1.2.3.4 -j DROP";
            IpTablesChainSet chains = new IpTablesChainSet(4);

            IpTablesRule irule = IpTablesRule.Parse(rule, null, chains, 4);

            Assert.Equal(rule, irule.GetActionCommand());
        }

        [Fact]
        public void TestParsingWithMultipleSpaces()
        {
            String rule = "-A INPUT -s   1.2.3.4   -j DROP";
            IpTablesChainSet chains = new IpTablesChainSet(4);

            IpTablesRule.Parse(rule, null, chains, 4);
        }

        [Fact]
        public void TestParsingWithSpaceAtEnd()
        {
            String rule = "-A INPUT -s 1.2.3.4 -j DROP ";
            IpTablesChainSet chains = new IpTablesChainSet(4);

            IpTablesRule.Parse(rule, null, chains, 4);
        }

        [Fact]
        public void TestParsingWithSpaceAtStart()
        {
            String rule = " -A INPUT -s 1.2.3.4 -j DROP";
            IpTablesChainSet chains = new IpTablesChainSet(4);

            IpTablesRule.Parse(rule, null, chains, 4);
        }
        [Fact]
        public void TestParsingWithSpacesAtStart()
        {
            String rule = "  -A INPUT -s 1.2.3.4 -j DROP";
            IpTablesChainSet chains = new IpTablesChainSet(4);

            IpTablesRule.Parse(rule, null, chains, 4);
        }

        [Fact]
        public void TestCoreDropingUdp()
        {
            String rule = "-A INPUT -p udp -j DROP";
            IpTablesChainSet chains = new IpTablesChainSet(4);

            IpTablesRule irule = IpTablesRule.Parse(rule, null, chains, 4);

            Assert.Equal(rule, irule.GetActionCommand());
        }

        [Fact]
        public void TestCoreFragmenting()
        {
            String rule = "-A INPUT ! -f -j test";
            IpTablesChainSet chains = new IpTablesChainSet(4);

            IpTablesRule irule = IpTablesRule.Parse(rule, null, chains, 4);

            Assert.Equal(rule, irule.GetActionCommand());
        }

        [Fact]
        public void TestCoreDropingDestinationEquality()
        {
            String rule = "-A INPUT -d 1.2.3.4/16 -j DROP";
            IpTablesChainSet chains = new IpTablesChainSet(4);

            IpTablesRule irule1 = IpTablesRule.Parse(rule, null, chains, 4);
            IpTablesRule irule2 = IpTablesRule.Parse(rule, null, chains, 4);

            Assert.True(irule2.Compare(irule1));
        }

        [Fact]
        public void TestCoreDropingInterfaceEquality()
        {
            String rule = "-A INPUT -i eth0 -j DROP";
            IpTablesChainSet chains = new IpTablesChainSet(4);

            IpTablesRule irule1 = IpTablesRule.Parse(rule, null, chains, 4);
            IpTablesRule irule2 = IpTablesRule.Parse(rule, null, chains, 4);

            Assert.True(irule2.Compare(irule1));
        }

        [Fact]
        public void TestCoreDropingSourceEquality()
        {
            String rule = "-A INPUT -s 1.2.3.4 -j DROP";
            IpTablesChainSet chains = new IpTablesChainSet(4);

            IpTablesRule irule1 = IpTablesRule.Parse(rule, null, chains, 4);
            IpTablesRule irule2 = IpTablesRule.Parse(rule, null, chains, 4);

            Assert.True(irule2.Compare(irule1));
        }

        [Fact]
        public void TestCoreDropingUdpEquality()
        {
            String rule = "-A INPUT -p udp -j DROP";
            IpTablesChainSet chains = new IpTablesChainSet(4);

            IpTablesRule irule1 = IpTablesRule.Parse(rule, null, chains, 4);
            IpTablesRule irule2 = IpTablesRule.Parse(rule, null, chains, 4);

            Assert.True(irule2.Compare(irule1));
        }

        [Fact]
        public void TestCoreFragmentingEquality()
        {
            String rule = "-A INPUT ! -f -j test";
            IpTablesChainSet chains = new IpTablesChainSet(4);

            IpTablesRule irule1 = IpTablesRule.Parse(rule, null, chains, 4);
            IpTablesRule irule2 = IpTablesRule.Parse(rule, null, chains, 4);

            Assert.True(irule2.Compare(irule1));
        }

        [Theory]
        [InlineData("-A INPUT --protocol tcp -j ACCEPT", "-A INPUT -p tcp -j ACCEPT")]
        [InlineData("-A INPUT ! --protocol tcp -j ACCEPT", "-A INPUT ! -p tcp -j ACCEPT")]
        [InlineData("-A INPUT --source 10.0.0.1/24 -j ACCEPT", "-A INPUT -s 10.0.0.1/24 -j ACCEPT")]
        [InlineData("-A INPUT ! --source 10.0.0.1/24 -j ACCEPT", "-A INPUT ! -s 10.0.0.1/24 -j ACCEPT")]
        [InlineData("-A INPUT --destination 192.0.2.5 -j ACCEPT", "-A INPUT -d 192.0.2.5 -j ACCEPT")]
        [InlineData("-A INPUT ! --destination 192.0.2.5 -j ACCEPT", "-A INPUT ! -d 192.0.2.5 -j ACCEPT")]
        [InlineData("-A INPUT --in-interface eth0+ -j ACCEPT", "-A INPUT -i eth0+ -j ACCEPT")]
        [InlineData("-A INPUT ! --in-interface eth0+ -j ACCEPT", "-A INPUT ! -i eth0+ -j ACCEPT")]
        [InlineData("-A INPUT --out-interface eth1 -j ACCEPT", "-A INPUT -o eth1 -j ACCEPT")]
        [InlineData("-A INPUT ! --out-interface eth1 -j ACCEPT", "-A INPUT ! -o eth1 -j ACCEPT")]
        [InlineData("-A INPUT --fragment -j ACCEPT", "-A INPUT -f -j ACCEPT")]
        [InlineData("-A INPUT ! --fragment -j ACCEPT", "-A INPUT ! -f -j ACCEPT")]
        [InlineData("-A INPUT --jump ACCEPT", "-A INPUT -j ACCEPT")]
        [InlineData("-A INPUT --goto NEXT_CHAIN", "-A INPUT -g NEXT_CHAIN")]
        [InlineData("-A INPUT --set-counters 12 34 -j ACCEPT", "-A INPUT -c 12 34 -j ACCEPT")]
        public void TestCoreOptionRoundTrip(string input, string expected)
        {
            RuleParseAssert.RoundTrips(input, expected);
        }
    }
}
