using System;
using IPTables.Net.Iptables;
using NUnit.Framework;

namespace IPTables.Net.Tests
{
    [TestFixture]
    internal class SingleCoreRuleParseTests
    {
        [Test]
        public void TestCoreDropingDestination()
        {
            String rule = "-A INPUT -d 1.2.3.4/16 -j DROP";
            String chain;

            IpTablesRule irule = IpTablesRule.Parse(rule, null, null);

            Assert.AreEqual(rule, "-A " + irule.Chain + " " + irule.GetCommand());
        }

        [Test]
        public void TestCoreDropingInterface()
        {
            String rule = "-A INPUT -i eth0 -j DROP";
            String chain;

            IpTablesRule irule = IpTablesRule.Parse(rule, null, null);

            Assert.AreEqual(rule, irule.GetFullCommand());
        }

        [Test]
        public void TestCoreDropingSource()
        {
            String rule = "-A INPUT -s 1.2.3.4 -j DROP";
            String chain;

            IpTablesRule irule = IpTablesRule.Parse(rule, null, null);

            Assert.AreEqual(rule, irule.GetFullCommand());
        }

        [Test]
        public void TestCoreDropingUdp()
        {
            String rule = "-A INPUT -p udp -j DROP";
            String chain;

            IpTablesRule irule = IpTablesRule.Parse(rule, null, null);

            Assert.AreEqual(rule, irule.GetFullCommand());
        }

        [Test]
        public void TestCoreFragmenting()
        {
            String rule = "-A INPUT ! -f -j test";
            String chain;

            IpTablesRule irule = IpTablesRule.Parse(rule, null, null);

            Assert.AreEqual(rule, irule.GetFullCommand());
        }

        [Test]
        public void TestCoreDropingDestinationEquality()
        {
            String rule = "-A INPUT -d 1.2.3.4/16 -j DROP";
            String chain;

            IpTablesRule irule1 = IpTablesRule.Parse(rule, null, null);
            IpTablesRule irule2 = IpTablesRule.Parse(rule, null, null);

            Assert.AreEqual(irule1, irule2);
        }

        [Test]
        public void TestCoreDropingInterfaceEquality()
        {
            String rule = "-A INPUT -i eth0 -j DROP";
            String chain;

            IpTablesRule irule1 = IpTablesRule.Parse(rule, null, null);
            IpTablesRule irule2 = IpTablesRule.Parse(rule, null, null);

            Assert.AreEqual(irule1, irule2);
        }

        [Test]
        public void TestCoreDropingSourceEquality()
        {
            String rule = "-A INPUT -s 1.2.3.4 -j DROP";
            String chain;

            IpTablesRule irule1 = IpTablesRule.Parse(rule, null, null);
            IpTablesRule irule2 = IpTablesRule.Parse(rule, null, null);

            Assert.AreEqual(irule1, irule2);
        }

        [Test]
        public void TestCoreDropingUdpEquality()
        {
            String rule = "-A INPUT -p udp -j DROP";
            String chain;

            IpTablesRule irule1 = IpTablesRule.Parse(rule, null, null);
            IpTablesRule irule2 = IpTablesRule.Parse(rule, null, null);

            Assert.AreEqual(irule1, irule2);
        }

        [Test]
        public void TestCoreFragmentingEquality()
        {
            String rule = "-A INPUT ! -f -j test";
            String chain;

            IpTablesRule irule1 = IpTablesRule.Parse(rule, null, null);
            IpTablesRule irule2 = IpTablesRule.Parse(rule, null, null);

            Assert.AreEqual(irule1, irule2);
        }
    }
}