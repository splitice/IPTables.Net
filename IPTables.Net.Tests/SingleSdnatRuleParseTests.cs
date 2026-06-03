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
        
    }
}