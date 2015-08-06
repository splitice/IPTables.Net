using System;
using IPTables.Net.Iptables;
using NUnit.Framework;

namespace IPTables.Net.Tests
{
    [TestFixture]
    internal class SingleLogRuleParseTests
    {
        [Test]
        public void TestLogWithPrefix()
        {
            String rule = "-A INPUT -j LOG --log-prefix 'IPTABLES (Rule ATTACKED): ' --log-level 7";
            IpTablesChainSet chains = new IpTablesChainSet(4);

            IpTablesRule irule = IpTablesRule.Parse(rule, null, chains, 4);

            Assert.AreEqual(rule, irule.GetActionCommand());
        }
    }
}