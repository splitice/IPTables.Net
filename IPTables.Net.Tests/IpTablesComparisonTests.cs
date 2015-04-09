using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using IPTables.Net.Iptables;
using NUnit.Framework;

namespace IPTables.Net.Tests
{
    [TestFixture]
    class IpTablesComparisonTests
    {
        [Test]
        public void TestComparisonMultiport()
        {
            String rule = "-A INPUT -p tcp -j RETURN -m multiport --dports 79,22 -m comment --comment TCP";

            IpTablesChainSet chains = new IpTablesChainSet(4);
            IpTablesRule r1 = IpTablesRule.Parse(rule, null, chains);
            IpTablesRule r2 = IpTablesRule.Parse(rule, null, chains);

            Assert.IsTrue(r1.Equals(r2));
        }

        [Test]
        public void TestLimitComparison()
        {
            String rule = "-A INPUT -m limit --limit 100/second --limit-burst 7";
            IpTablesChainSet chains = new IpTablesChainSet(4);

            IpTablesRule irule = IpTablesRule.Parse(rule, null, chains);

            Assert.AreEqual(rule, irule.GetActionCommand());

            IpTablesRule irule2 = IpTablesRule.Parse(rule, null, chains);

            Assert.AreEqual(irule2, irule);
        }

        [Test]
        public void TestDifficultCharacters()
        {
            String rule = "-A kY9xlwGhPJW6N1QCHoRg -t mangle -p tcp -d 107.1.107.1 -g x_ComPlex -m comment --comment 'ABC||+sPeC14l=|1' -m tcp --dport 81";
            IpTablesChainSet chains = new IpTablesChainSet(4);

            IpTablesRule irule = IpTablesRule.Parse(rule, null, chains);

            Assert.AreEqual(rule, irule.GetActionCommand());

            IpTablesRule irule2 = IpTablesRule.Parse(rule, null, chains);

            Assert.AreEqual(irule2, irule);
        }
    }
}
