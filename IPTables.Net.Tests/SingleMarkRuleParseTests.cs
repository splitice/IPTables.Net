using System;
using IPTables.Net.Iptables;
using NUnit.Framework;

namespace IPTables.Net.Tests
{
    [TestFixture]
    internal class SingleMarkRuleParseTests
    {
        [Test]
        public void TestXmark()
        {
            String rule = "-A INPUT -p tcp -j MARK --set-xmark 0xFF";
            String ruleExpect = "-A INPUT -p tcp -j MARK --set-xmark 0xFF";
            IpTablesChainSet chains = new IpTablesChainSet(4);

            IpTablesRule irule = IpTablesRule.Parse(rule, null, chains);

            Assert.AreEqual(ruleExpect, irule.GetActionCommand());
        }

        [Test]
        public void TestAndMark()
        {
            Int32 mark = 0;
            String rule = "-A INPUT -p tcp -j MARK --and-mark 0x" + mark.ToString("X");
            String ruleExpect = "-A INPUT -p tcp -j MARK --set-xmark 0x0";
            IpTablesChainSet chains = new IpTablesChainSet(4);

            IpTablesRule irule = IpTablesRule.Parse(rule, null, chains);

            Assert.AreEqual(ruleExpect, irule.GetActionCommand());
        }

        [Test]
        public void TestOrMark()
        {
            Int32 mark = 0;
            String rule = "-A INPUT -p tcp -j MARK --or-mark " + mark;
            String ruleExpect = "-A INPUT -p tcp -j MARK --set-xmark 0x" + mark.ToString("X") + "/0x" + mark.ToString("X");
            IpTablesChainSet chains = new IpTablesChainSet(4);

            IpTablesRule irule = IpTablesRule.Parse(rule, null, chains);

            Assert.AreEqual(ruleExpect, irule.GetActionCommand());
        }

        [Test]
        public void TestXorMark()
        {
            Int32 mark = 0;
            String rule = "-A INPUT -p tcp -j MARK --xor-mark " + mark;
            String ruleExpect = "-A INPUT -p tcp -j MARK --set-xmark 0x" + mark.ToString("X") + "/0x0";
            IpTablesChainSet chains = new IpTablesChainSet(4);

            IpTablesRule irule = IpTablesRule.Parse(rule, null, chains);

            Assert.AreEqual(ruleExpect, irule.GetActionCommand());
        }
    }
}