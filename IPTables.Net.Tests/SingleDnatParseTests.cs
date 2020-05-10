using System;
using IPTables.Net.Iptables;
using IPTables.Net.Iptables.Modules.Comment;
using NUnit.Framework;

namespace IPTables.Net.Tests
{
    [TestFixture]
    internal class SingleDnatParseTests
    {
        [Test]
        public void DnatTest1()
        {
            String rule = "-A A+B -p tcp -j DNAT --to-destination 1.2.3.4";
            IpTablesChainSet chains = new IpTablesChainSet(4);

            IpTablesRule irule = IpTablesRule.Parse(rule, null, chains, 4);

            Assert.AreEqual(rule, irule.GetActionCommand());
            Assert.IsTrue(irule.Compare(IpTablesRule.Parse(rule, null, chains, 4)));
        }

    }
}