using System;
using IPTables.Net.Iptables;
using NUnit.Framework;

namespace IPTables.Net.Tests
{
    [TestFixture]
    internal class SingleLimitRuleParseTests
    {

        [Test]
        public void TestRateCompare()
        {
            String rule = "-A ABC -m limit --limit 500/s";
            String rule2 = "-A ABC -m limit --limit 3000/s";
            IpTablesChainSet chains = new IpTablesChainSet(4);

            var r1 = IpTablesRule.Parse(rule, null, chains, 4);
            var r2 = IpTablesRule.Parse(rule2, null, chains, 4);

            Assert.IsFalse(r1.Compare(r2));
        }
    }
}