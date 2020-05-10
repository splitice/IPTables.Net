using System;
using System.Security.Cryptography;
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

        [Test]
        public void TestAppendRule()
        {
            IpTablesChainSet chains = new IpTablesChainSet(4);
            var rule = IpTablesRule.Parse("-A PREROUTING -s 1.1.1.1 -j TEST", null, chains, 4, "raw", IpTablesRule.ChainCreateMode.CreateNewChainIfNeeded);
            rule.AppendToRule("! -m devgroup --src-group 0x2");
        }
    }
}