using System;
using IPTables.Net.Iptables;

namespace IPTables.Net.Tests
{
    public class SingleDnatRuleParseTests
    {
        [Fact]
        public void TestDnatSingleSource()
        {
            String rule = "-A PREROUTING -t nat -d 1.1.1.1/24 -j DNAT --to-destination 2.2.2.2";
            IpTablesChainSet chains = new IpTablesChainSet(4);

            IpTablesRule irule = IpTablesRule.Parse(rule, null, chains, 4);

            Assert.Equal(rule, irule.GetActionCommand());
        }

        [Fact]
        public void TestDnatRangeSourceAndEquality()
        {
            String rule = "-A POSTROUTING -t nat -d 1.1.1.1/24 -j DNAT --to-destination 2.2.2.1-2.2.2.250";
            IpTablesChainSet chains = new IpTablesChainSet(4);

            IpTablesRule irule1 = IpTablesRule.Parse(rule, null, chains, 4);
            IpTablesRule irule2 = IpTablesRule.Parse(rule, null, chains, 4);

            Assert.True(irule2.Compare(irule1));
            Assert.Equal(rule, irule1.GetActionCommand());
            Assert.Equal(rule, irule2.GetActionCommand());
        }
    }
}