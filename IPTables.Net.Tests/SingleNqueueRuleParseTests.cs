using System;
using IPTables.Net.Iptables;
using NUnit.Framework;

namespace IPTables.Net.Tests
{
    [TestFixture]
    internal class SingleNqueueRuleParseTests
    {
        [Test]
        public void TestXmark()
        {
            String rule = "-A INPUT -j NFQUEUE --queue-num 1 --queue-bypass";
            IpTablesChainSet chains = new IpTablesChainSet();

            IpTablesRule irule = IpTablesRule.Parse(rule, null, chains);

            Assert.AreEqual(rule, irule.GetActionCommandParamters());
        }
    }
}