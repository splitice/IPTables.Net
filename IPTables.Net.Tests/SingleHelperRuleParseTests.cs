using System;
using IPTables.Net.Iptables;
using NUnit.Framework;

namespace IPTables.Net.Tests
{
    [TestFixture]
    internal class SingleHelperRuleParseTests
    {
        [Test]
        public void TestNotHelper()
        {
            String rule = "-A INPUT -m helper ! --helper cba -j ACCEPT";
            IpTablesChainSet chains = new IpTablesChainSet();

            IpTablesRule irule = IpTablesRule.Parse(rule, null, chains);

            Assert.AreEqual(rule, irule.GetFullCommand());
        }

        [Test]
        public void TestHelper()
        {
            String rule = "-A INPUT -m helper ! --helper abc -j ACCEPT";
            IpTablesChainSet chains = new IpTablesChainSet();

            IpTablesRule irule = IpTablesRule.Parse(rule, null, chains);

            Assert.AreEqual(rule, irule.GetFullCommand());
        }
    }
}