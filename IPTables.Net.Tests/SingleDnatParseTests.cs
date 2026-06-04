using System;
using IPTables.Net.Iptables;
using IPTables.Net.Iptables.Modules.Comment;

namespace IPTables.Net.Tests
{
    public class SingleDnatParseTests
    {
        [Fact]
        public void DnatTest1()
        {
            String rule = "-A A+B -p tcp -j DNAT --to-destination 1.2.3.4";
            IpTablesChainSet chains = new IpTablesChainSet(4);

            IpTablesRule irule = IpTablesRule.Parse(rule, null, chains, 4);

            Assert.Equal(rule, irule.GetActionCommand());
            Assert.True(irule.Compare(IpTablesRule.Parse(rule, null, chains, 4)));
        }

    }
}