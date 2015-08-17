using System;
using IPTables.Net.Iptables;
using NUnit.Framework;

namespace IPTables.Net.Tests
{
    [TestFixture]
    internal class IPTablesRuleTests
    {
        [Test]
        public void TestDefaultChain()
        {
            IpTablesChainSet chains = new IpTablesChainSet(4);
            var rule = IpTablesRule.Parse("-A PREROUTING -s 1.1.1.1 -j TEST", null, chains, 4, "raw", IpTablesRule.ChainCreateMode.CreateNewChainIfNeeded);
            Assert.AreEqual("raw", rule.Chain.Table);
        }
    }
}