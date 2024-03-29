﻿using System;
using IPTables.Net.Iptables;
using NUnit.Framework;

namespace IPTables.Net.Tests
{
    [TestFixture]
    internal class SingleMarkRuleParseTests
    {
        [Test]
        public void MatchMarkDec()
        {
            String rule = "-A INPUT -p tcp -j ACCEPT -m mark --mark 13041408/0xFFFF00";
            String ruleExpect = "-A INPUT -p tcp -j ACCEPT -m mark --mark 0xC6FF00/0xFFFF00";
            IpTablesChainSet chains = new IpTablesChainSet(4);

            IpTablesRule irule = IpTablesRule.Parse(rule, null, chains, 4);

            Assert.AreEqual(ruleExpect, irule.GetActionCommand());
            Assert.IsTrue(IpTablesRule.Parse(ruleExpect, null, chains, 4).Compare(irule));
        }

        [Test]
        public void MatchMarkHex()
        {
            String rule = "-A INPUT -p tcp -j ACCEPT -m mark --mark 0xc6ff00/0xFFFF00";
            String ruleExpect = "-A INPUT -p tcp -j ACCEPT -m mark --mark 0xC6FF00/0xFFFF00";
            IpTablesChainSet chains = new IpTablesChainSet(4);

            IpTablesRule irule = IpTablesRule.Parse(rule, null, chains, 4);

            Assert.AreEqual(ruleExpect, irule.GetActionCommand());
            Assert.IsTrue(IpTablesRule.Parse(ruleExpect, null, chains, 4).Compare(irule));
        }


        [Test]
        public void TestXmark()
        {
            String rule = "-A INPUT -p tcp -j MARK --set-xmark 0xFF";
            String ruleExpect = "-A INPUT -p tcp -j MARK --set-xmark 0xFF";
            IpTablesChainSet chains = new IpTablesChainSet(4);

            IpTablesRule irule = IpTablesRule.Parse(rule, null, chains, 4);

            Assert.AreEqual(ruleExpect, irule.GetActionCommand());
        }

        [Test]
        public void TestAndMark()
        {
            Int32 mark = 0;
            String rule = "-A INPUT -p tcp -j MARK --and-mark 0x" + mark.ToString("X");
            String ruleExpect = "-A INPUT -p tcp -j MARK --set-xmark 0x0";
            IpTablesChainSet chains = new IpTablesChainSet(4);

            IpTablesRule irule = IpTablesRule.Parse(rule, null, chains, 4);

            Assert.AreEqual(ruleExpect, irule.GetActionCommand());
        }

        [Test]
        public void TestOrMark()
        {
            Int32 mark = 0;
            String rule = "-A INPUT -p tcp -j MARK --or-mark " + mark;
            String ruleExpect = "-A INPUT -p tcp -j MARK --set-xmark 0x" + mark.ToString("X") + "/0x" + mark.ToString("X");
            IpTablesChainSet chains = new IpTablesChainSet(4);

            IpTablesRule irule = IpTablesRule.Parse(rule, null, chains, 4);

            Assert.AreEqual(ruleExpect, irule.GetActionCommand());
        }

        [Test]
        public void TestXorMark()
        {
            Int32 mark = 0;
            String rule = "-A INPUT -p tcp -j MARK --xor-mark " + mark;
            String ruleExpect = "-A INPUT -p tcp -j MARK --set-xmark 0x" + mark.ToString("X") + "/0x0";
            IpTablesChainSet chains = new IpTablesChainSet(4);

            IpTablesRule irule = IpTablesRule.Parse(rule, null, chains, 4);

            Assert.AreEqual(ruleExpect, irule.GetActionCommand());
        }
    }
}