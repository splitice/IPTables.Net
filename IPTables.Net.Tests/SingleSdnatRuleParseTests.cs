using System;
using IPTables.Net.Iptables;

namespace IPTables.Net.Tests
{
    public class SingleSdnatRuleParseTests
    {
        [Fact]
        public void TestSnatSingleSource()
        {
            String rule = "-A PREROUTING -t nat -j SDNAT --to-source 78.141.209.124 --to-destination 104.236.152.141:80 --ctmark 145 --ctmask 1";
            IpTablesChainSet chains = new IpTablesChainSet(4);

            IpTablesRule irule = IpTablesRule.Parse(rule, null, chains, 4);

            Assert.Equal(rule, irule.GetActionCommand());
        }

        [Theory]
        [InlineData("-A PREROUTING -t nat -j SDNAT --to-source 78.141.209.124", "-A PREROUTING -t nat -j SDNAT --to-source 78.141.209.124")]
        [InlineData("-A PREROUTING -t nat -j SDNAT --to-destination 104.236.152.141:80", "-A PREROUTING -t nat -j SDNAT --to-destination 104.236.152.141:80")]
        [InlineData("-A PREROUTING -t nat -j SDNAT --random", "-A PREROUTING -t nat -j SDNAT --random")]
        [InlineData("-A PREROUTING -t nat -j SDNAT --persistent", "-A PREROUTING -t nat -j SDNAT --persistent")]
        [InlineData("-A PREROUTING -t nat -j SDNAT --add-seqadj", "-A PREROUTING -t nat -j SDNAT --add-seqadj")]
        [InlineData("-A PREROUTING -t nat -j SDNAT --ctmark 0x91", "-A PREROUTING -t nat -j SDNAT --ctmark 145")]
        [InlineData("-A PREROUTING -t nat -j SDNAT --ctmask 0x1", "-A PREROUTING -t nat -j SDNAT --ctmask 1")]
        [InlineData("-A PREROUTING -t nat -j SDNAT --to-source 78.141.209.124 --to-destination 104.236.152.141:80 --random --add-seqadj --persistent --ctmark 145 --ctmask 1", "-A PREROUTING -t nat -j SDNAT --to-source 78.141.209.124 --to-destination 104.236.152.141:80 --random --add-seqadj --persistent --ctmark 145 --ctmask 1")]
        public void TestSdnatOptionRoundTrip(string input, string expected)
        {
            RuleParseAssert.RoundTrips(input, expected);
        }
        
    }
}
