using System;
using IPTables.Net.Iptables;
using NUnit.Framework;

namespace IPTables.Net.Tests
{
    [TestFixture]
    internal class SingleMultiportRuleParseTests
    {
        [Test]
        public void TestMultiports()
        {
            String rule = "-A INPUT -p tcp -m multiport --ports 80,1000:1080";
            IpTablesChainSet chains = new IpTablesChainSet();

            IpTablesRule irule = IpTablesRule.Parse(rule, null, chains);

            Assert.AreEqual(rule, irule.GetFullCommand());
        }
    }
}