using System;
using IPTables.Net.Iptables;
using NUnit.Framework;

namespace IPTables.Net.Tests
{
    [TestFixture]
    internal class SingleSdnatRuleParseTests
    {
        [Test]
        public void TestSnatSingleSource()
        {
            String rule = "-A PREROUTING -t nat -j SDNAT --to-source 78.141.209.124 --to-destination 104.236.152.141:80 --ctmark 145 --ctmask 1";
            IpTablesChainSet chains = new IpTablesChainSet(4);

            IpTablesRule irule = IpTablesRule.Parse(rule, null, chains, 4);

            Assert.AreEqual(rule, irule.GetActionCommand());
        }
        
    }
}