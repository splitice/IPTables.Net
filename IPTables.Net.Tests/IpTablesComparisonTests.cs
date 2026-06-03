using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Text;
using IPTables.Net.Iptables;

namespace IPTables.Net.Tests
{
    public class IpTablesComparisonTests
    {
        [Fact]
        public void TestIpCompare()
        {
            Assert.Equal(IPAddress.IPv6Loopback, IPAddress.Parse("::1"));
            Assert.Equal(IPAddress.Parse("::0.0.0.1"), IPAddress.Parse("::1"));
        }

        [Fact]
        public void TestComparisonMultiport()
        {
            String rule = "-A INPUT -p tcp -j RETURN -m multiport --dports 79,22 -m comment --comment TCP";

            IpTablesChainSet chains = new IpTablesChainSet(4);
            IpTablesRule r1 = IpTablesRule.Parse(rule, null, chains, 4);
            IpTablesRule r2 = IpTablesRule.Parse(rule, null, chains, 4);

            Assert.True(r1.Compare(r2));
        }

        [Fact]
        public void TestLimitComparison()
        {
            String rule = "-A INPUT -m limit --limit 100/second --limit-burst 7";
            IpTablesChainSet chains = new IpTablesChainSet(4);

            IpTablesRule irule = IpTablesRule.Parse(rule, null, chains, 4);

            Assert.Equal(rule, irule.GetActionCommand());

            IpTablesRule irule2 = IpTablesRule.Parse(rule, null, chains, 4);

            Assert.True(irule2.Compare(irule));
        }

        [Fact]
        public void TestDifficultCharacters()
        {
            String rule = "-A kY9xlwGhPJW6N1QCHoRg -t mangle -p tcp -d 107.1.107.1 -g x_ComPlex -m comment --comment 'ABC||+sPeC14l=|1' -m tcp --dport 81";
            IpTablesChainSet chains = new IpTablesChainSet(4);

            IpTablesRule irule = IpTablesRule.Parse(rule, null, chains, 4);

            Assert.Equal(rule, irule.GetActionCommand());

            IpTablesRule irule2 = IpTablesRule.Parse(rule, null, chains, 4);

            Assert.True(irule2.Compare(irule));
        }
    }
}
