using System;
using IPTables.Net.Iptables;
using NUnit.Framework;

namespace IPTables.Net.Tests
{
    [TestFixture]
    internal class SingleSynProxyRuleParseTests
    {
        [Test]
        public void TestSingleRule()
        {
            String rule = "-A INPUT -p tcp -i eth0 -j SYNPROXY --mss 1460 --wscale 9 --sack-perm --timestamp -m state --state UNTRACKED,INVALID";
            IpTablesChainSet chains = new IpTablesChainSet();

            IpTablesRule irule = IpTablesRule.Parse(rule, null, chains);

            Assert.AreEqual(rule, irule.GetActionCommand());
        }
    }
}