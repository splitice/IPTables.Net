using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using NUnit.Framework;

namespace IPTables.Net.Tests
{
    [TestFixture]
    class SingleCoreRuleParseTests
    {
        [Test]
        public void TestCoreFragmenting()
        {
            String rule = "-A INPUT ! -f -j test";
            String chain;

            IpTablesRule irule = IpTablesRule.Parse(rule, out chain);

            Assert.AreEqual(rule, "-A " + chain + " " + irule.GetCommand("filter"));
        }

        [Test]
        public void TestCoreDropingSource()
        {
            String rule = "-A INPUT -s 1.2.3.4 -j DROP";
            String chain;

            IpTablesRule irule = IpTablesRule.Parse(rule, out chain);

            Assert.AreEqual(rule, "-A " + chain + " " + irule.GetCommand("filter"));
        }

        [Test]
        public void TestCoreDropingDestination()
        {
            String rule = "-A INPUT -d 1.2.3.4/16 -j DROP";
            String chain;

            IpTablesRule irule = IpTablesRule.Parse(rule, out chain);

            Assert.AreEqual(rule, "-A "+chain+" "+irule.GetCommand("filter"));
        }

        [Test]
        public void TestCoreDropingInterface()
        {
            String rule = "-A INPUT -i eth0 -j DROP";
            String chain;

            IpTablesRule irule = IpTablesRule.Parse(rule, out chain);

            Assert.AreEqual(rule, "-A " + chain + " " + irule.GetCommand("filter"));
        }

        [Test]
        public void TestCoreDropinUdp()
        {
            String rule = "-A INPUT -p udp -j DROP";
            String chain;

            IpTablesRule irule = IpTablesRule.Parse(rule, out chain);

            Assert.AreEqual(rule, "-A " + chain + " " + irule.GetCommand("filter"));
        }
    }
}
