using System;
using IPTables.Net.Iptables;
using IPTables.Net.Iptables.Modules.Connmark;

namespace IPTables.Net.Tests
{
    public class SingleConnmarkRuleParseTests
    {
        [Fact]
        public void TestXmark()
        {
            String rule = "-A INPUT -p tcp -j CONNMARK --set-xmark 0xFF";
            String ruleExpect = "-A INPUT -p tcp -j CONNMARK --set-xmark 0xFF";
            IpTablesChainSet chains = new IpTablesChainSet(4);

            IpTablesRule irule = IpTablesRule.Parse(rule, null, chains, 4);

            Assert.Equal(ruleExpect, irule.GetActionCommand());
        }


        [Fact]
        public void TestMatchMark1()
        {
            String rule = "-A INPUT -p tcp -m connmark --mark 0xFF";
            String ruleExpect = "-A INPUT -p tcp -m connmark --mark 0xFF";
            IpTablesChainSet chains = new IpTablesChainSet(4);

            IpTablesRule irule = IpTablesRule.Parse(rule, null, chains, 4);

            Assert.Equal(ruleExpect, irule.GetActionCommand());
        }
        [Fact]
        public void TestMatchMark2()
        {
            String rule = "-A INPUT -p tcp -m connmark --mark 255";
            String ruleExpect = "-A INPUT -p tcp -m connmark --mark 0xFF";
            IpTablesChainSet chains = new IpTablesChainSet(4);

            IpTablesRule irule = IpTablesRule.Parse(rule, null, chains, 4);

            Assert.Equal(ruleExpect, irule.GetActionCommand());
        }
        [Fact]
        public void TestMatchMark3()
        {
            String rule = "-A INPUT -p tcp -m connmark --mark 255/0xFF";
            String ruleExpect = "-A INPUT -p tcp -m connmark --mark 0xFF/0xFF";
            IpTablesChainSet chains = new IpTablesChainSet(4);

            IpTablesRule irule = IpTablesRule.Parse(rule, null, chains, 4);
            IpTablesRule irule2 = IpTablesRule.Parse(ruleExpect, null, chains, 4);

            Assert.Equal(ruleExpect, irule.GetActionCommand());
            Assert.True(irule.Compare(irule2));
        }

        [Fact]
        public void TestAndMark()
        {
            Int32 mark = 0;
            String rule = "-A INPUT -p tcp -j CONNMARK --and-mark 0x" + mark.ToString("X");
            String ruleExpect = "-A INPUT -p tcp -j CONNMARK --set-xmark 0x0";
            IpTablesChainSet chains = new IpTablesChainSet(4);

            IpTablesRule irule = IpTablesRule.Parse(rule, null, chains, 4);

            Assert.Equal(ruleExpect, irule.GetActionCommand());
        }

        [Fact]
        public void TestSetMark1()
        {
            String rule = "-A INPUT -j CONNMARK --set-xmark 0x200/0x1ffff00";
            String ruleExpect = "-A INPUT -j CONNMARK --set-xmark 0x200/0x1FFFF00";
            IpTablesChainSet chains = new IpTablesChainSet(4);

            IpTablesRule irule = IpTablesRule.Parse(rule, null, chains, 4);

            Assert.Equal(ruleExpect, irule.GetActionCommand());
            Assert.True(IpTablesRule.Parse(ruleExpect, null, chains, 4).Compare(irule));
        }

        [Fact]
        public void TestSetMark2()
        {
            String rule = "-A INPUT -j CONNMARK --set-xmark "+0x200+"/0x1ffff00";
            String ruleExpect = "-A INPUT -j CONNMARK --set-xmark 0x200/0x1FFFF00";
            IpTablesChainSet chains = new IpTablesChainSet(4);

            IpTablesRule irule = IpTablesRule.Parse(rule, null, chains, 4);

            Assert.Equal(ruleExpect, irule.GetActionCommand());
            Assert.True(IpTablesRule.Parse(ruleExpect, null, chains, 4).Compare(irule));
        }

        [Fact]
        public void TestSetMark3()
        {
            String rule = "-A INPUT -j CONNMARK --set-xmark " + 0x200 + "/0x1ffff00";
            String ruleExpect = "-A INPUT -j CONNMARK --set-xmark 0x200/0x1ffff00";
            IpTablesChainSet chains = new IpTablesChainSet(4);

            IpTablesRule irule = IpTablesRule.Parse(rule, null, chains, 4);
            
            Assert.True(IpTablesRule.Parse(ruleExpect, null, chains, 4).Compare(irule));
        }

        [Fact]
        public void TestOrMark()
        {
            Int32 mark = 0;
            String rule = "-A INPUT -p tcp -j CONNMARK --or-mark " + mark;
            String ruleExpect = "-A INPUT -p tcp -j CONNMARK --set-xmark 0x" + mark.ToString("X") + "/0x" + mark.ToString("X");
            IpTablesChainSet chains = new IpTablesChainSet(4);

            IpTablesRule irule = IpTablesRule.Parse(rule, null, chains, 4);

            Assert.Equal(ruleExpect, irule.GetActionCommand());
        }

        [Fact]
        public void TestXorMark()
        {
            Int32 mark = 0;
            String rule = "-A INPUT -p tcp -j CONNMARK --xor-mark " + mark;
            String ruleExpect = "-A INPUT -p tcp -j CONNMARK --set-xmark 0x" + mark.ToString("X") + "/0x0";
            IpTablesChainSet chains = new IpTablesChainSet(4);

            IpTablesRule irule = IpTablesRule.Parse(rule, null, chains, 4);

            Assert.Equal(ruleExpect, irule.GetActionCommand());
        }

        [Fact]
        public void TestXMarkMasked()
        {
            String rule = "-A RETURN_AFWCON -j CONNMARK --set-xmark 0x1/0x1";
            IpTablesChainSet chains = new IpTablesChainSet(4);

            IpTablesRule irule = IpTablesRule.Parse(rule, null, chains, 4);

            Assert.Equal(rule, irule.GetActionCommand());
        }


        [Fact]
        public void TestRestoreMark()
        {
            String rule = "-A PREROUTING -j CONNMARK --restore-mark --ctmask 0x11 --nfmask 0x3FFFF00";
            IpTablesChainSet chains = new IpTablesChainSet(4);

            IpTablesRule irule = IpTablesRule.Parse(rule, null, chains, 4);

            Assert.Equal(rule, irule.GetActionCommand());
        }

        [Theory]
        [InlineData("-A INPUT -m connmark ! --mark 0xFF", "-A INPUT -m connmark ! --mark 0xFF")]
        [InlineData("-A INPUT -j CONNMARK --set-mark 0xFF", "-A INPUT -j CONNMARK --set-xmark 0xFF")]
        [InlineData("-A INPUT -j CONNMARK --and-mark 0x0", "-A INPUT -j CONNMARK --set-xmark 0x0")]
        [InlineData("-A INPUT -j CONNMARK --or-mark 0", "-A INPUT -j CONNMARK --set-xmark 0x0/0x0")]
        [InlineData("-A INPUT -j CONNMARK --xor-mark 0", "-A INPUT -j CONNMARK --set-xmark 0x0/0x0")]
        [InlineData("-A INPUT -j CONNMARK --save-mark --ctmask 0x11 --nfmask 0x3FFFF00", "-A INPUT -j CONNMARK --save-mark --ctmask 0x11 --nfmask 0x3FFFF00")]
        public void TestConnmarkOptionRoundTrip(string input, string expected)
        {
            RuleParseAssert.RoundTrips(input, expected);
        }
    }
}
