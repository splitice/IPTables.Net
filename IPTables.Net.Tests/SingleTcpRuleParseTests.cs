using System;
using IPTables.Net.Iptables;
using NUnit.Framework;

namespace IPTables.Net.Tests
{
    [TestFixture]
    internal class SingleTcpRuleParseTests
    {
        [Test]
        public void TestDropFragmentedTcpDns()
        {
            String rule = "-A INPUT -p tcp ! -f -j DROP -m tcp --sport 53";
            IpTablesChainSet chains = new IpTablesChainSet();

            IpTablesRule irule = IpTablesRule.Parse(rule, null, chains);

            Assert.AreEqual(rule, irule.GetActionCommandParamters());
        }

        [Test]
        public void TestDropFragmentedTcpDnsEquality()
        {
            String rule = "-A INPUT -p tcp ! -f -j DROP -m tcp --sport 53";
            IpTablesChainSet chains = new IpTablesChainSet();

            IpTablesRule irule1 = IpTablesRule.Parse(rule, null, chains);
            IpTablesRule irule2 = IpTablesRule.Parse(rule, null, chains);

            Assert.AreEqual(irule1, irule2);
        }

        [Test]
        public void TestCoreSportEquality()
        {
            String rule = "-A INPUT -p tcp -j DROP -m tcp --sport 1";
            IpTablesChainSet chains = new IpTablesChainSet();

            IpTablesRule irule1 = IpTablesRule.Parse(rule, null, chains);
            IpTablesRule irule2 = IpTablesRule.Parse(rule, null, chains);

            Assert.AreEqual(irule1, irule2);
        }

        [Test]
        public void TestCoreSportZeroValue()
        {
            String rule = "-A INPUT -p tcp -j DROP -m tcp --sport 0";
            IpTablesChainSet chains = new IpTablesChainSet();

            IpTablesRule irule1 = IpTablesRule.Parse(rule, null, chains);

            Assert.AreEqual(rule, irule1.GetActionCommandParamters());
        }
    }
}