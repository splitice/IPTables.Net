using System;
using IPTables.Net.Iptables;

namespace IPTables.Net.Tests
{
    public class SingleRecentRuleParseTests
    {
        [Fact]
        public void TestSet()
        {
            String rule = "-A ATTK_CHECK -m recent --set --name ATTK";
            IpTablesChainSet chains = new IpTablesChainSet(4);

            IpTablesRule irule = IpTablesRule.Parse(rule, null, chains, 4);

            Assert.Equal(rule, irule.GetActionCommand());
        }

        [Fact]
        public void TestUpdate()
        {
            String rule = "-A ATTK_CHECK -m recent --update --name ATTK --seconds 180 --hitcount 20 -j ATTACKED";
            IpTablesChainSet chains = new IpTablesChainSet(4);

            IpTablesRule irule = IpTablesRule.Parse(rule, null, chains, 4);

            Assert.Equal(rule, irule.GetActionCommand());
        }

        [Fact]
        public void TestCompare1()
        {
            String rule = "-A ATTK_CHECK -m recent --rcheck --name BANNED --seconds 180 --reap --rttl -j ATTACKED";
            IpTablesChainSet chains = new IpTablesChainSet(4);

            Assert.True(IpTablesRule.Parse(rule, null, chains, 4).Compare(IpTablesRule.Parse(rule, null, chains, 4)));
        }

        [Theory]
        [InlineData("-A ATTK_CHECK -m recent --remove --name BANNED", "-A ATTK_CHECK -m recent --remove --name BANNED")]
        [InlineData("-A ATTK_CHECK -m recent --set --rsource", "-A ATTK_CHECK -m recent --set")]
        [InlineData("-A ATTK_CHECK -m recent --set --rdest", "-A ATTK_CHECK -m recent --set --rdest")]
        [InlineData("-A ATTK_CHECK -m recent --update --seconds 60 --hitcount 5 --reap --rttl", "-A ATTK_CHECK -m recent --update --seconds 60 --hitcount 5 --reap --rttl")]
        [InlineData("-A ATTK_CHECK -m recent --rcheck --mask 255.255.255.0", "-A ATTK_CHECK -m recent --rcheck --mask 255.255.255.0")]
        public void TestRecentOptionRoundTrip(string input, string expected)
        {
            RuleParseAssert.RoundTrips(input, expected);
        }
    }
}
