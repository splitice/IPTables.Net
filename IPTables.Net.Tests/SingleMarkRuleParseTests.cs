using System;
using IPTables.Net.Iptables;

namespace IPTables.Net.Tests
{
    public class SingleMarkRuleParseTests
    {
        [Fact]
        public void MatchMarkDec()
        {
            String rule = "-A INPUT -p tcp -j ACCEPT -m mark --mark 13041408/0xFFFF00";
            String ruleExpect = "-A INPUT -p tcp -j ACCEPT -m mark --mark 0xC6FF00/0xFFFF00";
            IpTablesChainSet chains = new IpTablesChainSet(4);

            IpTablesRule irule = IpTablesRule.Parse(rule, null, chains, 4);

            Assert.Equal(ruleExpect, irule.GetActionCommand());
            Assert.True(IpTablesRule.Parse(ruleExpect, null, chains, 4).Compare(irule));
        }

        [Fact]
        public void MatchMarkHex()
        {
            String rule = "-A INPUT -p tcp -j ACCEPT -m mark --mark 0xc6ff00/0xFFFF00";
            String ruleExpect = "-A INPUT -p tcp -j ACCEPT -m mark --mark 0xC6FF00/0xFFFF00";
            IpTablesChainSet chains = new IpTablesChainSet(4);

            IpTablesRule irule = IpTablesRule.Parse(rule, null, chains, 4);

            Assert.Equal(ruleExpect, irule.GetActionCommand());
            Assert.True(IpTablesRule.Parse(ruleExpect, null, chains, 4).Compare(irule));
        }


        [Fact]
        public void TestXmark()
        {
            String rule = "-A INPUT -p tcp -j MARK --set-xmark 0xFF";
            String ruleExpect = "-A INPUT -p tcp -j MARK --set-xmark 0xFF";
            IpTablesChainSet chains = new IpTablesChainSet(4);

            IpTablesRule irule = IpTablesRule.Parse(rule, null, chains, 4);

            Assert.Equal(ruleExpect, irule.GetActionCommand());
        }

        [Fact]
        public void TestAndMark()
        {
            Int32 mark = 0;
            String rule = "-A INPUT -p tcp -j MARK --and-mark 0x" + mark.ToString("X");
            String ruleExpect = "-A INPUT -p tcp -j MARK --set-xmark 0x0";
            IpTablesChainSet chains = new IpTablesChainSet(4);

            IpTablesRule irule = IpTablesRule.Parse(rule, null, chains, 4);

            Assert.Equal(ruleExpect, irule.GetActionCommand());
        }

        [Fact]
        public void TestOrMark()
        {
            Int32 mark = 0;
            String rule = "-A INPUT -p tcp -j MARK --or-mark " + mark;
            String ruleExpect = "-A INPUT -p tcp -j MARK --set-xmark 0x" + mark.ToString("X") + "/0x" + mark.ToString("X");
            IpTablesChainSet chains = new IpTablesChainSet(4);

            IpTablesRule irule = IpTablesRule.Parse(rule, null, chains, 4);

            Assert.Equal(ruleExpect, irule.GetActionCommand());
        }

        [Fact]
        public void TestXorMark()
        {
            Int32 mark = 0;
            String rule = "-A INPUT -p tcp -j MARK --xor-mark " + mark;
            String ruleExpect = "-A INPUT -p tcp -j MARK --set-xmark 0x" + mark.ToString("X") + "/0x0";
            IpTablesChainSet chains = new IpTablesChainSet(4);

            IpTablesRule irule = IpTablesRule.Parse(rule, null, chains, 4);

            Assert.Equal(ruleExpect, irule.GetActionCommand());
        }

        [Theory]
        [InlineData("-A INPUT -m mark ! --mark 0xFF", "-A INPUT -m mark ! --mark 0xFF")]
        [InlineData("-A INPUT -j MARK --set-mark 0xFF", "-A INPUT -j MARK --set-xmark 0xFF")]
        [InlineData("-A INPUT -j MARK --set-mark 0xF/0xF0", "-A INPUT -j MARK --set-xmark 0xF/0xFF")]
        [InlineData("-A INPUT -j MARK --and-mark 0x0", "-A INPUT -j MARK --set-xmark 0x0")]
        [InlineData("-A INPUT -j MARK --or-mark 0", "-A INPUT -j MARK --set-xmark 0x0/0x0")]
        [InlineData("-A INPUT -j MARK --xor-mark 0", "-A INPUT -j MARK --set-xmark 0x0/0x0")]
        public void TestMarkOptionRoundTrip(string input, string expected)
        {
            RuleParseAssert.RoundTrips(input, expected);
        }
    }
}
