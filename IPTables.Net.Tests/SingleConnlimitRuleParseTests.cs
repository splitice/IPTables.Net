using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using NUnit.Framework;

namespace IPTables.Net.Tests
{
    [TestFixture]
    class SingleConnlimitRuleParseTests
    {
        [Test]
        public void TestDropConnectionLimit()
        {
            String rule = "-A INPUT -p tcp -j DROP -m connlimit --connlimit-above 10";
            String chain;

            IpTablesRule irule = IpTablesRule.Parse(rule, out chain);

            Assert.AreEqual(rule, "-A " + chain + " " + irule.GetCommand("filter"));
        }
    }
}
