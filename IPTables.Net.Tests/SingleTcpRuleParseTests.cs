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
    }
}