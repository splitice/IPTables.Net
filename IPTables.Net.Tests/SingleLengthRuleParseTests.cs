using System;
using IPTables.Net.Iptables;

namespace IPTables.Net.Tests
{
    public class SingleLengthRuleParseTests
    {
        [Fact]
        public void TestLengthRange()
        {
            String rule = "-A INPUT -m length --length 10:100 -j ACCEPT";
            IpTablesChainSet chains = new IpTablesChainSet(4);

            IpTablesRule irule = IpTablesRule.Parse(rule, null, chains, 4);

            Assert.Equal(rule, irule.GetActionCommand());
        }
        [Fact]
        public void TestNotLengthRange()
        {
            String rule = "-A INPUT -m length ! --length 10:100 -j ACCEPT";
            IpTablesChainSet chains = new IpTablesChainSet(4);

            IpTablesRule irule = IpTablesRule.Parse(rule, null, chains, 4);

            Assert.Equal(rule, irule.GetActionCommand());
        }

        [Fact]
        public void TestNotLength()
        {
            String rule = "-A INPUT -m length ! --length 10 -j ACCEPT";
            IpTablesChainSet chains = new IpTablesChainSet(4);

            IpTablesRule irule = IpTablesRule.Parse(rule, null, chains, 4);

            Assert.Equal(rule, irule.GetActionCommand());
        }
    }
}