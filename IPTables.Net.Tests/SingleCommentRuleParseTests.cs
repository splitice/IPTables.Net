using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using NUnit.Framework;

namespace IPTables.Net.Tests
{
    [TestFixture]
    class SingleCommentRuleParseTests
    {
        [Test]
        public void TestDropFragmentedTcpDnsWithComment()
        {
            String rule = "-A INPUT -p tcp ! -f -j DROP -m tcp --sport 53 -m comment --comment \"this is a test rule\"";
            String chain;

            IpTablesRule irule = IpTablesRule.Parse(rule, out chain);

            Assert.AreEqual(rule, "-A " + chain + " " + irule.GetCommand("filter"));
        }
    }
}
