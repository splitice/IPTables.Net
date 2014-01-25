using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

using NUnit.Framework;

namespace IPTables.Net.Tests
{
    [TestFixture]
    class SingleTcpRuleParseTests
    {
        [Test]
        public void TestDropFragmentedTcpDns()
        {
            String rule = "-A INPUT -p tcp ! -f -j DROP -m tcp --sport 53";
            String chain;

            IpTablesRule irule = IpTablesRule.Parse(rule, out chain);

            Assert.AreEqual(rule, "-A " + chain + " " + irule.GetCommand("filter"));
        }
    }
}
