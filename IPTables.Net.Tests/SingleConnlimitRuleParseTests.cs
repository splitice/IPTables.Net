using System;
using IPTables.Net.Iptables;
using NUnit.Framework;

namespace IPTables.Net.Tests
{
    [TestFixture]
    internal class SingleConnlimitRuleParseTests
    {
        [Test]
        public void TestDropConnectionLimit()
        {
            String rule = "-A INPUT -p tcp -j DROP -m connlimit --connlimit-above 10";
            IpTablesChainSet chains = new IpTablesChainSet();

            IpTablesRule irule = IpTablesRule.Parse(rule, null, chains);

            Assert.AreEqual(rule, irule.GetActionCommandParamters());
        }

        [Test]
        public void TestDropConnectionLimitEquality()
        {
            String rule = "-A INPUT -p tcp -j DROP -m connlimit --connlimit-above 10";
            IpTablesChainSet chains = new IpTablesChainSet();

            IpTablesRule irule1 = IpTablesRule.Parse(rule, null, chains);
            IpTablesRule irule2 = IpTablesRule.Parse(rule, null, chains);

            Assert.AreEqual(irule1, irule2);
        }
    }
}