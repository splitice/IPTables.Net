using System;
using IPTables.Net.Iptables;

namespace IPTables.Net.Tests
{
    public class SingleRtsParseTests
    {
        [Fact]
        public void TestSimple()
        {
            String rule = "-A INPUT -p tcp ! -f -j RTS";
            IpTablesChainSet chains = new IpTablesChainSet(4);

            IpTablesRule irule = IpTablesRule.Parse(rule, null, chains, 4);

            Assert.Equal(rule, irule.GetActionCommand());
        }

        [Fact]
        public void TestWithDest()
        {
            String rule = "-A INPUT -p tcp ! -f -j RTS --rts-dst 1.1.1.1";
            IpTablesChainSet chains = new IpTablesChainSet(4);

            IpTablesRule irule1 = IpTablesRule.Parse(rule, null, chains, 4);
            IpTablesRule irule2 = IpTablesRule.Parse(rule, null, chains, 4);

            Assert.True(irule2.Compare(irule1));
        }
    }
}