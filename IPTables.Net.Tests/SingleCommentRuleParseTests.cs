using System;
using IPTables.Net.Iptables;
using IPTables.Net.Iptables.Modules.Comment;

namespace IPTables.Net.Tests
{
    public class SingleCommentRuleParseTests
    {
        [Fact]
        public void TestDropFragmentedTcpDnsWithComment()
        {
            String rule = "-A INPUT -p tcp ! -f -j DROP -m tcp --sport 53 -m comment --comment 'this is a test rule'";
            IpTablesChainSet chains = new IpTablesChainSet(4);

            IpTablesRule irule = IpTablesRule.Parse(rule, null, chains, 4);

            Assert.Equal(rule, irule.GetActionCommand());
        }

        [Fact]
        public void TestDropFragmentedTcpDnsWithCommentEquality()
        {
            String rule = "-A INPUT -p tcp ! -f -j DROP -m tcp --sport 53 -m comment --comment 'this is a test rule'";
            IpTablesChainSet chains = new IpTablesChainSet(4);

            IpTablesRule irule1 = IpTablesRule.Parse(rule, null, chains, 4);
            IpTablesRule irule2 = IpTablesRule.Parse(rule, null, chains, 4);

            Assert.True(irule2.Compare(irule1));
        }


        [Fact]
        public void TestBlankComment ()
        {
            String rule = "-A INPUT -p tcp ! -f -j DROP -m comment --comment '' -m tcp --dport 53";
            IpTablesChainSet chains = new IpTablesChainSet(4);

            IpTablesRule irule1 = IpTablesRule.Parse(rule, null, chains, 4);
            IpTablesRule irule2 = IpTablesRule.Parse(rule, null, chains, 4);

            Assert.True(irule2.Compare(irule1));
        }

        [Fact]
        public void TestAddCommentAfter()
        {
            String rule1 = "-A INPUT -p tcp ! -f -j DROP -m tcp --sport 53";
            String rule2 = "-A INPUT -p tcp ! -f -j DROP -m tcp --sport 53 -m comment --comment 'this is a test rule'";
            IpTablesChainSet chains = new IpTablesChainSet(4);

            IpTablesRule irule1 = IpTablesRule.Parse(rule1, null, chains);
            irule1.SetComment("this is a test rule");

            Assert.Equal(rule2, irule1.GetActionCommand());
        }
    }
}