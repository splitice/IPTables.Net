using System;
using IPTables.Net.Iptables;
using NUnit.Framework;

namespace IPTables.Net.Tests
{
    [TestFixture]
    internal class SinglePolyfillTests
    {
        [Test]
        public void TestPolyfillParse()
        {
            String rule = "-A INPUT -m unknown --unknown";
            IpTablesChainSet chains = new IpTablesChainSet(4);

            IpTablesRule irule = IpTablesRule.Parse(rule, null, chains);

            Assert.AreEqual(rule, irule.GetActionCommand());
        }

        [Test]
        public void TestPolyfillParseAdditionalOptionsAfter()
        {
            String rule = "-A INPUT -m unknown --unknown -p tcp -d 1.1.1.1 -m tcp --dport 80";
            IpTablesChainSet chains = new IpTablesChainSet(4);

            IpTablesRule irule = IpTablesRule.Parse(rule, null, chains);

            Assert.AreEqual(rule, irule.GetActionCommand());
        }
    }
}