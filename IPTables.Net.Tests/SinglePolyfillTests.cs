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

        [Test]
        public void TestPolyfillArgumentsComparison1()
        {
            String rule = "-A INPUT -m unknown --unknown --unknown-2 1111 -p tcp -d 1.1.1.1 -m tcp --dport 80";
            IpTablesChainSet chains = new IpTablesChainSet(4);

            Assert.AreEqual(IpTablesRule.Parse(rule, null, chains), IpTablesRule.Parse(rule, null, chains));
        }

        [Test]
        public void TestPolyfillArgumentsComparison2()
        {
            String rule = "-A INPUT -m unknown --unknown --unknown-2 1111 -m unknown2 --unknown2 -p tcp -d 1.1.1.1 -m tcp --dport 80";
            IpTablesChainSet chains = new IpTablesChainSet(4);

            Assert.AreEqual(IpTablesRule.Parse(rule, null, chains), IpTablesRule.Parse(rule, null, chains));
        }

        [Test]
        public void TestPolyfillArgumentsComparison3()
        {
            String rule = "-A INPUT -m unknown --unknown --unknown-2 1111 -m unknown2 --unknown2 -p tcp -d 1.1.1.1 -m tcp --dport 80";
            String rule2 = "-A INPUT -m unknown2 --unknown2 -m unknown --unknown --unknown-2 1111 -p tcp -d 1.1.1.1 -m tcp --dport 80";
            IpTablesChainSet chains = new IpTablesChainSet(4);

            Assert.AreEqual(IpTablesRule.Parse(rule, null, chains), IpTablesRule.Parse(rule2, null, chains));
        }

        [Test]
        public void TestPolyfillArgumentsComparison4()
        {
            String rule = "-A INPUT -m unknown --unknown --unknown-2 \'this has spaces & a symbol\' -m unknown2 --unknown2 -p tcp -d 1.1.1.1 -m tcp --dport 80";
            String rule2 = "-A INPUT -m unknown2 --unknown2 -m unknown --unknown --unknown-2 \'this has spaces & a symbol\' -p tcp -d 1.1.1.1 -m tcp --dport 80";
            IpTablesChainSet chains = new IpTablesChainSet(4);

            Assert.AreEqual(IpTablesRule.Parse(rule, null, chains), IpTablesRule.Parse(rule2, null, chains));
        }
    }
}