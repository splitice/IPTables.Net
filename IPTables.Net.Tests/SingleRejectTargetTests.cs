using System;
using IPTables.Net.Iptables;
using NUnit.Framework;

namespace IPTables.Net.Tests
{
    [TestFixture]
    internal class SingleRejectTargetTests
    {
        [Test]
        public void TestRejectWithIcmp()
        {
            String rule = "-A ufw-user-limit -j REJECT --reject-with icmp-port-unreachable";
            IpTablesChainSet chains = new IpTablesChainSet(4);

            IpTablesRule irule = IpTablesRule.Parse(rule, null, chains, 4);

            Assert.AreEqual(rule, irule.GetActionCommand());
        }
    }
}