using System;
using IPTables.Net.Iptables;
using NUnit.Framework;

namespace IPTables.Net.Tests
{
    [TestFixture]
    internal class SingleRtsParseTests
    {
        [Test]
        public void TestSimple()
        {
            String rule = "-A INPUT -p tcp ! -f -j RTS";
            IpTablesChainSet chains = new IpTablesChainSet(4);

            IpTablesRule irule = IpTablesRule.Parse(rule, null, chains, 4);

            Assert.AreEqual(rule, irule.GetActionCommand());
        }

        [Test]
        public void TestWithDest()
        {
            String rule = "-A INPUT -p tcp ! -f -j RTS --rts-dst 1.1.1.1";
            IpTablesChainSet chains = new IpTablesChainSet(4);

            IpTablesRule irule1 = IpTablesRule.Parse(rule, null, chains, 4);
            IpTablesRule irule2 = IpTablesRule.Parse(rule, null, chains, 4);

            Assert.IsTrue(irule2.Compare(irule1));
        }
    }
}