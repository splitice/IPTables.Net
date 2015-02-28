using System;
using IPTables.Net.Iptables;
using NUnit.Framework;

namespace IPTables.Net.Tests
{
    [TestFixture]
    internal class SingleConnmarkRuleParseTests
    {
        [Test]
        public void TestXmark()
        {
            String rule = "-A INPUT -p tcp -j CONNMARK --set-xmark 0xFF";
            String ruleExpect = "-A INPUT -p tcp -j CONNMARK --set-xmark 0xFF";
            IpTablesChainSet chains = new IpTablesChainSet();

            IpTablesRule irule = IpTablesRule.Parse(rule, null, chains);

            Assert.AreEqual(ruleExpect, irule.GetActionCommand());
        }

        [Test]
        public void TestAndMark()
        {
            Int32 mark = 0;
            String rule = "-A INPUT -p tcp -j CONNMARK --and-mark 0x" + mark.ToString("X");
            String ruleExpect = "-A INPUT -p tcp -j CONNMARK --set-xmark 0x0";
            IpTablesChainSet chains = new IpTablesChainSet();

            IpTablesRule irule = IpTablesRule.Parse(rule, null, chains);

            Assert.AreEqual(ruleExpect, irule.GetActionCommand());
        }

        [Test]
        public void TestOrMark()
        {
            Int32 mark = 0;
            String rule = "-A INPUT -p tcp -j CONNMARK --or-mark " + mark;
            String ruleExpect = "-A INPUT -p tcp -j CONNMARK --set-xmark 0x" + mark.ToString("X") + "/0x" + mark.ToString("X");
            IpTablesChainSet chains = new IpTablesChainSet();

            IpTablesRule irule = IpTablesRule.Parse(rule, null, chains);

            Assert.AreEqual(ruleExpect, irule.GetActionCommand());
        }

        [Test]
        public void TestXorMark()
        {
            Int32 mark = 0;
            String rule = "-A INPUT -p tcp -j CONNMARK --xor-mark " + mark;
            String ruleExpect = "-A INPUT -p tcp -j CONNMARK --set-xmark 0x" + mark.ToString("X") + "/0x0";
            IpTablesChainSet chains = new IpTablesChainSet();

            IpTablesRule irule = IpTablesRule.Parse(rule, null, chains);

            Assert.AreEqual(ruleExpect, irule.GetActionCommand());
        }

        [Test]
        public void TestXMarkMasked()
        {
            String rule = "-A RETURN_AFWCON -j CONNMARK --set-xmark 0x1/0x1";
            IpTablesChainSet chains = new IpTablesChainSet();

            IpTablesRule irule = IpTablesRule.Parse(rule, null, chains);

            Assert.AreEqual(rule, irule.GetActionCommand());
        }
        
    }
}