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
            IpTablesChainSet chains = new IpTablesChainSet(4);

            IpTablesRule irule = IpTablesRule.Parse(rule, null, chains, 4);

            Assert.AreEqual(rule, irule.GetActionCommand());
        }

        [Test]
        public void TestDropFragmentedTcpDnsEquality()
        {
            String rule = "-A INPUT -p tcp ! -f -j DROP -m tcp --sport 53";
            IpTablesChainSet chains = new IpTablesChainSet(4);

            IpTablesRule irule1 = IpTablesRule.Parse(rule, null, chains, 4);
            IpTablesRule irule2 = IpTablesRule.Parse(rule, null, chains, 4);

            Assert.AreEqual(irule1, irule2);
        }

        [Test]
        public void TestCoreSportEquality()
        {
            String rule = "-A INPUT -p tcp -j DROP -m tcp --sport 1";
            IpTablesChainSet chains = new IpTablesChainSet(4);

            IpTablesRule irule1 = IpTablesRule.Parse(rule, null, chains, 4);
            IpTablesRule irule2 = IpTablesRule.Parse(rule, null, chains, 4);

            Assert.AreEqual(irule1, irule2);
        }

        [Test]
        public void TestCoreSportZeroValue()
        {
            String rule = "-A INPUT -p tcp -j DROP -m tcp --sport 0";
            IpTablesChainSet chains = new IpTablesChainSet(4);

            IpTablesRule irule1 = IpTablesRule.Parse(rule, null, chains, 4);

            Assert.AreEqual(rule, irule1.GetActionCommand());
        }
    }
}