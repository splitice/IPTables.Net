using System;
using IPTables.Net.Iptables;
using NUnit.Framework;

namespace IPTables.Net.Tests
{
    [TestFixture]
    internal class SingleStatisticParseTests
    {
        [Test]
        public void Test1()
        {
            String rule = "-A FORWARD -m statistic --mode nth --every 3 --packet 1";
            IpTablesChainSet chains = new IpTablesChainSet(4);

            IpTablesRule irule = IpTablesRule.Parse(rule, null, chains, 4);

            Assert.AreEqual(rule, irule.GetActionCommand());
        }
    }
}