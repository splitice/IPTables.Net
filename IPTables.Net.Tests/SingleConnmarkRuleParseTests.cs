using System;
using IPTables.Net.Iptables;
using IPTables.Net.Iptables.Modules.Connmark;
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
            IpTablesChainSet chains = new IpTablesChainSet(4);

            IpTablesRule irule = IpTablesRule.Parse(rule, null, chains, 4);

            Assert.AreEqual(ruleExpect, irule.GetActionCommand());
        }


        [Test]
        public void TestMatchMark1()
        {
            String rule = "-A INPUT -p tcp -m connmark --mark 0xFF";
            String ruleExpect = "-A INPUT -p tcp -m connmark --mark 0xFF";
            IpTablesChainSet chains = new IpTablesChainSet(4);

            IpTablesRule irule = IpTablesRule.Parse(rule, null, chains, 4);

            Assert.AreEqual(ruleExpect, irule.GetActionCommand());
        }
        [Test]
        public void TestMatchMark2()
        {
            String rule = "-A INPUT -p tcp -m connmark --mark 255";
            String ruleExpect = "-A INPUT -p tcp -m connmark --mark 0xFF";
            IpTablesChainSet chains = new IpTablesChainSet(4);

            IpTablesRule irule = IpTablesRule.Parse(rule, null, chains, 4);

            Assert.AreEqual(ruleExpect, irule.GetActionCommand());
        }
        [Test]
        public void TestMatchMark3()
        {
            String rule = "-A INPUT -p tcp -m connmark --mark 255/0xFF";
            String ruleExpect = "-A INPUT -p tcp -m connmark --mark 0xFF/0xFF";
            IpTablesChainSet chains = new IpTablesChainSet(4);

            IpTablesRule irule = IpTablesRule.Parse(rule, null, chains, 4);
            IpTablesRule irule2 = IpTablesRule.Parse(ruleExpect, null, chains, 4);

            Assert.AreEqual(ruleExpect, irule.GetActionCommand());
            Assert.IsTrue(irule.Compare(irule2));
        }

        [Test]
        public void TestAndMark()
        {
            Int32 mark = 0;
            String rule = "-A INPUT -p tcp -j CONNMARK --and-mark 0x" + mark.ToString("X");
            String ruleExpect = "-A INPUT -p tcp -j CONNMARK --set-xmark 0x0";
            IpTablesChainSet chains = new IpTablesChainSet(4);

            IpTablesRule irule = IpTablesRule.Parse(rule, null, chains, 4);

            Assert.AreEqual(ruleExpect, irule.GetActionCommand());
        }

        [Test]
        public void TestSetMark1()
        {
            String rule = "-A INPUT -j CONNMARK --set-xmark 0x200/0x1ffff00";
            String ruleExpect = "-A INPUT -j CONNMARK --set-xmark 0x200/0x1FFFF00";
            IpTablesChainSet chains = new IpTablesChainSet(4);

            IpTablesRule irule = IpTablesRule.Parse(rule, null, chains, 4);

            Assert.AreEqual(ruleExpect, irule.GetActionCommand());
            Assert.IsTrue(IpTablesRule.Parse(ruleExpect, null, chains, 4).Compare(irule));
        }

        [Test]
        public void TestSetMark2()
        {
            String rule = "-A INPUT -j CONNMARK --set-xmark "+0x200+"/0x1ffff00";
            String ruleExpect = "-A INPUT -j CONNMARK --set-xmark 0x200/0x1FFFF00";
            IpTablesChainSet chains = new IpTablesChainSet(4);

            IpTablesRule irule = IpTablesRule.Parse(rule, null, chains, 4);

            Assert.AreEqual(ruleExpect, irule.GetActionCommand());
            Assert.IsTrue(IpTablesRule.Parse(ruleExpect, null, chains, 4).Compare(irule));
        }

        [Test]
        public void TestSetMark3()
        {
            String rule = "-A INPUT -j CONNMARK --set-xmark " + 0x200 + "/0x1ffff00";
            String ruleExpect = "-A INPUT -j CONNMARK --set-xmark 0x200/0x1ffff00";
            IpTablesChainSet chains = new IpTablesChainSet(4);

            IpTablesRule irule = IpTablesRule.Parse(rule, null, chains, 4);
            
            Assert.IsTrue(IpTablesRule.Parse(ruleExpect, null, chains, 4).Compare(irule));
        }

        [Test]
        public void TestOrMark()
        {
            Int32 mark = 0;
            String rule = "-A INPUT -p tcp -j CONNMARK --or-mark " + mark;
            String ruleExpect = "-A INPUT -p tcp -j CONNMARK --set-xmark 0x" + mark.ToString("X") + "/0x" + mark.ToString("X");
            IpTablesChainSet chains = new IpTablesChainSet(4);

            IpTablesRule irule = IpTablesRule.Parse(rule, null, chains, 4);

            Assert.AreEqual(ruleExpect, irule.GetActionCommand());
        }

        [Test]
        public void TestXorMark()
        {
            Int32 mark = 0;
            String rule = "-A INPUT -p tcp -j CONNMARK --xor-mark " + mark;
            String ruleExpect = "-A INPUT -p tcp -j CONNMARK --set-xmark 0x" + mark.ToString("X") + "/0x0";
            IpTablesChainSet chains = new IpTablesChainSet(4);

            IpTablesRule irule = IpTablesRule.Parse(rule, null, chains, 4);

            Assert.AreEqual(ruleExpect, irule.GetActionCommand());
        }

        [Test]
        public void TestXMarkMasked()
        {
            String rule = "-A RETURN_AFWCON -j CONNMARK --set-xmark 0x1/0x1";
            IpTablesChainSet chains = new IpTablesChainSet(4);

            IpTablesRule irule = IpTablesRule.Parse(rule, null, chains, 4);

            Assert.AreEqual(rule, irule.GetActionCommand());
        }


        [Test]
        public void TestRestoreMark()
        {
            String rule = "-A PREROUTING -j CONNMARK --restore-mark --ctmask 0x11 --nfmask 0x3FFFF00";
            IpTablesChainSet chains = new IpTablesChainSet(4);

            IpTablesRule irule = IpTablesRule.Parse(rule, null, chains, 4);

            Assert.AreEqual(rule, irule.GetActionCommand());
        }
    }
}