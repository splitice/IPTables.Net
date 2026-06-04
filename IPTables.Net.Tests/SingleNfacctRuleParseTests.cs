using System;
using IPTables.Net.Iptables;

namespace IPTables.Net.Tests
{
    public class SingleNfacctRuleParseTests
    {
        [Fact]
        public void TestSmall()
        {
            String rule = "-A INPUT -j ACCEPT -m nfacct --nfacct-name test";
            IpTablesChainSet chains = new IpTablesChainSet(4);

            IpTablesRule irule = IpTablesRule.Parse(rule, null, chains, 4);

            Assert.Equal(rule, irule.GetActionCommand());
        }

        [Fact]
        public void TestQuote()
        {
            String rule = "-A INPUT -j ACCEPT -m nfacct --nfacct-name \"test\"";
            String rule2 = "-A INPUT -j ACCEPT -m nfacct --nfacct-name test";
            IpTablesChainSet chains = new IpTablesChainSet(4);

            IpTablesRule irule = IpTablesRule.Parse(rule, null, chains, 4);

            Assert.Equal(rule2, irule.GetActionCommand());
            Assert.True(IpTablesRule.Parse(rule2, null, chains, 4).Compare(irule));
        }

        [Fact]
        public void TestDoubleSpace()
        {
            String rule = "-A INPUT -j ACCEPT -m nfacct --nfacct-name  \"test\"";
            String rule2 = "-A INPUT -j ACCEPT -m nfacct --nfacct-name test";
            IpTablesChainSet chains = new IpTablesChainSet(4);

            IpTablesRule irule = IpTablesRule.Parse(rule, null, chains, 4);

            Assert.Equal(rule2, irule.GetActionCommand());
            Assert.True(IpTablesRule.Parse(rule2, null, chains, 4).Compare(irule));
        }
    }
}